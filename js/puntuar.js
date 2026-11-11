// Convierte los hechos DNS en puntos, nota A–F, veredicto y una tarjeta por control. Funciones puras.
import { LIMITE_BUSQUEDAS, LIMITE_VACIAS, recomendarSPF } from './spf.js';
import { recomendarDMARC } from './dmarc.js';
import { fuerzaDKIM } from './dkim.js';

// Reparto de los 100 puntos (explicado en /proceso/). DMARC pesa más porque es el único control
// que protege el remitente que ve la persona (la cabecera From:).
export const PESOS = { dmarc: 40, informes: 5, spf: 30, dkim: 15, dnssec: 5, mtasts: 3, tlsrpt: 2 };

export const NOTAS = [
  { nota: 'A', min: 90 },
  { nota: 'B', min: 75 },
  { nota: 'C', min: 60 },
  { nota: 'D', min: 40 },
  { nota: 'F', min: 0 },
];
export const TOPE_SIN_DMARC = 59; // sin DMARC que bloquee, como mucho D: el resto no impide la suplantación

export function notaDe(puntos) {
  return NOTAS.find((n) => puntos >= n.min).nota;
}

const redondear = (x) => Math.round(x * 10) / 10;

// ---------------------------------------------------------------- SPF
export function puntuarSPF(h) {
  const max = PESOS.spf;
  const t = { id: 'spf', titulo: 'SPF', max, nombre: h.dominio, actual: h.spf.registros.join('\n') || null, detalle: [] };
  const regs = h.spf.registros;
  const recomendado = recomendarSPF({ registros: regs, recibeCorreo: h.recibeCorreo, proveedor: h.proveedor });
  const conRec = (o) => ({ ...t, ...o, recomendado: recomendado && recomendado !== regs[0]?.trim() ? recomendado : null });

  if (!h.spf.consultado) return conRec({ estado: 'info', etiqueta: 'Sin respuesta', puntos: 0, explica: 'No se pudo leer el registro TXT del dominio.' });
  if (regs.length === 0) {
    return conRec({
      estado: 'mal', etiqueta: 'No tiene', puntos: 0,
      explica: h.recibeCorreo
        ? 'No hay lista de servidores autorizados: cualquier servidor del mundo puede decir que envía por este dominio.'
        : 'El dominio no usa correo, pero no lo declara. Con «v=spf1 -all» le dice a todos que ningún servidor envía en su nombre.',
    });
  }
  if (regs.length > 1) {
    return conRec({ estado: 'mal', etiqueta: `${regs.length} registros`, puntos: 0,
      explica: 'Hay más de un registro SPF. La norma dice que entonces ninguno vale (permerror): hay que fundirlos en uno.' });
  }
  const p = h.spf.parseado;
  const b = h.spf.busquedas;
  if (b) {
    t.detalle.push(`Búsquedas DNS: ${b.total} de ${LIMITE_BUSQUEDAS} permitidas${b.nodos.length > 1 ? ` (siguiendo ${b.nodos.length - 1} include/redirect)` : ''}.`);
    if (b.macros.length) t.detalle.push(`Usa macros (${b.macros.length}); esas ramas no se pueden seguir sin un correo real: cuentan 1 cada una.`);
  }
  if (b && (b.total > LIMITE_BUSQUEDAS || b.vacias > LIMITE_VACIAS)) {
    const motivo = b.total > LIMITE_BUSQUEDAS
      ? `necesita ${b.total} búsquedas DNS y el máximo es ${LIMITE_BUSQUEDAS}`
      : `tiene ${b.vacias} búsquedas vacías y el máximo es ${LIMITE_VACIAS}`;
    return { ...t, estado: 'mal', etiqueta: 'Se rompe', puntos: 5,
      explica: `El registro ${motivo}. Los servidores que lo revisan dan error (permerror) y tratan el SPF como roto. Quita include que ya no uses o cambia algunos por ip4/ip6.`,
      recomendado: null };
  }
  let puntos;
  let estado;
  let etiqueta;
  let explica;
  switch (p.all) {
    case '-':
      [puntos, estado, etiqueta] = [30, 'bien', 'Estricto (-all)'];
      explica = 'Publica la lista de servidores autorizados y pide rechazar al resto.';
      break;
    case '~':
      [puntos, estado, etiqueta] = [25, 'bien', 'Suave (~all)'];
      explica = 'Publica la lista y marca como sospechoso al resto. Con DMARC en quarantine o reject es lo que recomiendan M3AAWG y CISA; «-all» solo si ya conoces todos tus remitentes.';
      break;
    case '?':
      [puntos, estado, etiqueta] = [8, 'regular', 'Neutro (?all)'];
      explica = '«?all» dice «no sé» sobre los servidores que no están en la lista: no ayuda a frenar a un impostor.';
      break;
    case '+':
      [puntos, estado, etiqueta] = [0, 'mal', 'Abierto (+all)'];
      explica = '«+all» autoriza a cualquier servidor de Internet. Es como no tener SPF, o peor: da el visto bueno a los falsos.';
      break;
    default:
      if (p.redirect) {
        [puntos, estado, etiqueta] = [25, 'bien', 'Delegado (redirect)'];
        explica = `Usa la política de ${p.redirect}.`;
      } else {
        [puntos, estado, etiqueta] = [8, 'regular', 'Sin final'];
        explica = 'No termina en «all»: lo que no está en la lista queda como neutro («?all»).';
      }
  }
  if (b?.ptr) {
    puntos = Math.max(0, puntos - 3);
    t.detalle.push('Usa el mecanismo «ptr», que la RFC 7208 desaconseja (lento y poco fiable): −3 puntos.');
    if (estado === 'bien') estado = 'regular';
  }
  if (b?.errores.length) t.detalle.push(...b.errores.slice(0, 3).map((e) => `Ojo: ${e}.`));
  return conRec({ estado, etiqueta, puntos, explica });
}

// ---------------------------------------------------------------- DMARC
export function puntuarDMARC(h) {
  const max = PESOS.dmarc + PESOS.informes;
  const d = h.dmarc;
  const nombre = `_dmarc.${h.dominio}`;
  const heredado = d.origen === 'organizacional';
  const pd = d.parseado;
  const { registro: recomendado, paso } = recomendarDMARC({ dmarc: pd && !heredado ? pd : null, dominio: heredado ? h.organizacional : h.dominio, recibeCorreo: h.recibeCorreo });
  const t = { id: 'dmarc', titulo: 'DMARC', max, nombre: heredado ? d.nombre : nombre, actual: d.registros.join('\n') || null, detalle: [], paso };
  const rec = recomendado && !heredado && recomendado !== d.registro?.trim() ? recomendado : null;

  if (!d.consultado && !d.registro) return { ...t, estado: 'info', etiqueta: 'Sin respuesta', puntos: 0, politica: null, explica: 'No se pudo leer _dmarc.', recomendado: rec };
  if (!d.registro) {
    return { ...t, estado: 'mal', etiqueta: 'No tiene', puntos: 0, politica: null, recomendado: rec,
      explica: 'Nadie les dice a Gmail, Outlook y compañía qué hacer con un correo falso que use este dominio. Lo normal es que lo entreguen.' };
  }
  if (pd.errores.length) {
    return { ...t, estado: 'mal', etiqueta: 'Mal escrito', puntos: 0, politica: null, recomendado: rec, detalle: pd.errores,
      explica: 'El registro existe pero tiene errores, así que los servidores lo ignoran.' };
  }
  const politica = heredado ? pd.sp : pd.p;
  if (heredado) t.detalle.push(`No tiene registro propio: hereda el de ${h.organizacional} (para subdominios cuenta sp=${pd.sp}).`);
  const base = { none: 10, quarantine: 10 + 20 * (pd.pct / 100), reject: 10 + 30 * (pd.pct / 100) }[politica];
  let puntos = base;
  const textos = {
    none: 'Solo observa (p=none): pide informes, pero deja pasar los correos falsos.',
    quarantine: 'Pide mandar a spam (p=quarantine) los correos que no pasan SPF ni DKIM alineados.',
    reject: 'Pide rechazar (p=reject) los correos que no pasan SPF ni DKIM alineados. Es el nivel más alto.',
  };
  let explica = textos[politica];
  if (politica !== 'none' && pd.pct < 100) {
    explica += ` Pero solo al ${pd.pct} % de los correos (pct=${pd.pct}): el resto se trata como p=${politica === 'reject' ? 'quarantine' : 'none'}.`;
  }
  if (!heredado && politica !== 'none' && pd.sp === 'none') {
    puntos -= 5;
    t.detalle.push('sp=none: los subdominios (por ejemplo pagos.' + h.dominio + ') quedan sin protección. −5 puntos.');
  }
  if (pd.rua.length) { puntos += PESOS.informes; t.detalle.push(`Recibe informes agregados (rua) en ${pd.rua.length} ${pd.rua.length > 1 ? 'direcciones' : 'dirección'}: así ve quién envía en su nombre.`); }
  else t.detalle.push('Sin rua: no recibe informes, así que no sabe si alguien lo está suplantando.');
  t.detalle.push(`Alineación: SPF ${pd.aspf === 's' ? 'estricta' : 'relajada'}, DKIM ${pd.adkim === 's' ? 'estricta' : 'relajada'} (relajada acepta subdominios del mismo dominio).`);
  if (pd.avisos.length) t.detalle.push(...pd.avisos.map((a) => `Ojo: ${a}.`));
  const estado = politica === 'reject' && pd.pct === 100 ? 'bien' : politica === 'none' ? 'mal' : 'regular';
  const etiqueta = { none: 'Solo mira', quarantine: 'A spam', reject: 'Rechaza' }[politica] + (politica !== 'none' && pd.pct < 100 ? ` (${pd.pct} %)` : '');
  return { ...t, estado, etiqueta, puntos: redondear(Math.max(0, puntos)), politica, pct: pd.pct, sp: pd.sp, explica, recomendado: rec };
}

// ---------------------------------------------------------------- DKIM
export function puntuarDKIM(h, { sinCorreoBlindado = false } = {}) {
  const max = PESOS.dkim;
  const k = h.dkim;
  const t = { id: 'dkim', titulo: 'DKIM', max, detalle: [] };
  const sel = h.proveedor?.dkim ?? 'selector';
  const plantilla = { nombre: `${sel}._domainkey.${h.dominio}`, valor: 'v=DKIM1; k=rsa; p=<clave pública que te da tu proveedor de correo>' };
  if (sinCorreoBlindado) {
    return { ...t, estado: 'bien', etiqueta: 'No aplica', puntos: max, nombre: null, actual: null, recomendado: null,
      explica: 'El dominio no envía correo y lo declara (SPF nulo y DMARC reject): no necesita firmar nada.' };
  }
  if (!k.encontrados.length) {
    t.detalle.push(`Se probaron ${k.probados} selectores comunes (google, selector1, selector2, default, k1, s1…).`);
    if (k.fallidos) t.detalle.push(`${k.fallidos} consultas no respondieron.`);
    return { ...t, estado: 'info', etiqueta: 'No encontrado', puntos: 4, nombre: plantilla.nombre, actual: null, recomendado: plantilla.valor,
      explica: 'No apareció ninguna clave con los selectores comunes. Puede que exista con otro nombre: DKIM no se puede listar desde fuera. Si no lo tienes, actívalo en tu proveedor de correo.' };
  }
  const fuerzas = k.encontrados.map((c) => ({ ...c, fuerza: fuerzaDKIM(c) }));
  const vivas = fuerzas.filter((c) => c.fuerza !== 'revocada');
  for (const c of fuerzas) {
    const desc = c.revocada ? 'revocada (p vacío)' : `${c.tipo === 'ed25519' ? 'Ed25519' : `RSA ${c.bits ?? '¿?'} bits`}${c.prueba ? ', en modo prueba (t=y)' : ''}`;
    t.detalle.push(`Selector «${c.selector}»: ${desc}.`);
  }
  const mejor = vivas.some((c) => c.fuerza === 'fuerte') ? 'fuerte' : vivas.some((c) => c.fuerza === 'aceptable' || c.fuerza === 'desconocida') ? 'aceptable' : vivas.length ? 'debil' : 'revocada';
  const tabla = {
    fuerte: ['bien', 'Firma', max, 'Firma sus correos con una clave pública publicada: el receptor puede comprobar que el mensaje salió de sus servidores y no se alteró.'],
    aceptable: ['regular', 'Clave corta', 9, 'Firma sus correos, pero con una clave RSA de 1024 bits. Hoy se recomienda 2048.'],
    debil: ['mal', 'Clave débil', 3, 'La clave es menor de 1024 bits: la RFC 8301 dice que los receptores deben ignorarla.'],
    revocada: ['regular', 'Revocada', 4, 'Solo apareció una clave revocada (p vacío). Puede que use otro selector.'],
  };
  const [estado, etiqueta, puntos, explica] = tabla[mejor];
  return { ...t, estado, etiqueta, puntos, explica, nombre: `${fuerzas[0].selector}._domainkey.${h.dominio}`, actual: null,
    recomendado: mejor === 'fuerte' ? null : 'Genera una clave RSA de 2048 bits en tu proveedor y publica el nuevo selector.' };
}

// ---------------------------------------------------------------- extras
export function puntuarExtras(h) {
  const sinCorreo = !h.recibeCorreo;
  const tarjetas = [];
  tarjetas.push({
    id: 'dnssec', titulo: 'DNSSEC', max: PESOS.dnssec, nombre: null, actual: null, detalle: [],
    estado: h.dnssec ? 'bien' : 'regular', etiqueta: h.dnssec ? 'Firmado' : 'Sin firmar', puntos: h.dnssec ? PESOS.dnssec : 0,
    explica: h.dnssec
      ? 'Las respuestas DNS llegan firmadas y el resolutor las validó (bandera AD): es difícil falsificar estos registros en el camino.'
      : 'Las respuestas DNS no vienen firmadas. Alguien que controle la red podría falsificarlas (es el «pharming» del art. 269G). Se activa en el registrador o en el proveedor de DNS.',
    recomendado: null,
  });
  tarjetas.push({
    id: 'mtasts', titulo: 'MTA-STS', max: PESOS.mtasts, nombre: `_mta-sts.${h.dominio}`, actual: h.mtasts, detalle: [],
    estado: h.mtasts ? 'bien' : sinCorreo ? 'info' : 'regular', etiqueta: h.mtasts ? 'Activo' : sinCorreo ? 'No aplica' : 'No tiene',
    puntos: h.mtasts || sinCorreo ? PESOS.mtasts : 0,
    explica: h.mtasts
      ? 'Obliga a que el correo que recibe viaje cifrado (TLS) y con un certificado válido.'
      : sinCorreo ? 'No recibe correo: no hace falta.' : 'Protege el correo que recibes de que lo lean en el camino. No frena la suplantación, pero completa la protección. Además del TXT hay que publicar https://mta-sts.' + h.dominio + '/.well-known/mta-sts.txt.',
    recomendado: h.mtasts || sinCorreo ? null : 'v=STSv1; id=20261110T000000',
  });
  tarjetas.push({
    id: 'tlsrpt', titulo: 'TLS-RPT', max: PESOS.tlsrpt, nombre: `_smtp._tls.${h.dominio}`, actual: h.tlsrpt, detalle: [],
    estado: h.tlsrpt ? 'bien' : sinCorreo ? 'info' : 'regular', etiqueta: h.tlsrpt ? 'Activo' : sinCorreo ? 'No aplica' : 'No tiene',
    puntos: h.tlsrpt || sinCorreo ? PESOS.tlsrpt : 0,
    explica: h.tlsrpt ? 'Recibe informes cuando el cifrado del correo entrante falla.' : sinCorreo ? 'No recibe correo: no hace falta.' : 'Pide informes cuando otros servidores no logran entregarte correo cifrado.',
    recomendado: h.tlsrpt || sinCorreo ? null : `v=TLSRPTv1; rua=mailto:tlsrpt@${h.dominio}`,
  });
  tarjetas.push({
    id: 'bimi', titulo: 'BIMI', max: 0, nombre: `default._bimi.${h.dominio}`, actual: h.bimi, detalle: [],
    estado: 'info', etiqueta: h.bimi ? 'Tiene logo' : 'No tiene', puntos: 0,
    explica: h.bimi
      ? 'Publica su logo para que aparezca junto a sus correos. Solo funciona con DMARC en quarantine o reject.'
      : 'Opcional: muestra tu logo junto a tus correos. Exige DMARC en quarantine o reject (y en Gmail, un certificado de marca). No suma puntos.',
    recomendado: null,
  });
  return tarjetas;
}

// ---------------------------------------------------------------- MX
export function tarjetaMX(h) {
  const hosts = h.mx.map((m) => `${m.preferencia} ${m.host || '.'}`);
  if (h.nullMX) {
    return { id: 'mx', titulo: 'MX', max: 0, puntos: 0, estado: 'info', etiqueta: 'MX nulo', nombre: h.dominio, actual: hosts.join('\n'), detalle: [],
      explica: 'Declara con un MX nulo (RFC 7505) que no recibe correo.', recomendado: null };
  }
  if (!h.recibeCorreo) {
    return { id: 'mx', titulo: 'MX', max: 0, puntos: 0, estado: 'info', etiqueta: 'No recibe', nombre: h.dominio, actual: null, detalle: [],
      explica: 'No tiene servidores de correo (MX). Si no usa correo, lo correcto es blindarlo: SPF nulo y DMARC reject. Un dominio sin correo también se puede suplantar.',
      recomendado: null };
  }
  return { id: 'mx', titulo: 'MX', max: 0, puntos: 0, estado: 'info', etiqueta: 'Recibe correo', nombre: h.dominio, actual: hosts.join('\n'),
    detalle: h.proveedor ? [`Proveedor probable: ${h.proveedor.nombre}.`] : [],
    explica: `Recibe correo en ${h.mx.length} servidor${h.mx.length > 1 ? 'es' : ''}. Si recibe, casi seguro también envía: necesita SPF, DKIM y DMARC.`, recomendado: null };
}

// ---------------------------------------------------------------- veredicto
export const VEREDICTOS = {
  blindado: { titulo: 'Blindado', sub: 'No envía correo y lo declara', tono: 'frio', onoma: 'CLANK' },
  'muy-dificil': { titulo: 'Muy difícil de suplantar', sub: 'Los correos falsos se rechazan', tono: 'frio', onoma: 'BLOCK' },
  dificil: { titulo: 'Difícil de suplantar', sub: 'Pero hay una rendija', tono: 'frio', onoma: 'CLINK' },
  'a-medias': { titulo: 'Suplantable a medias', sub: 'Los falsos llegan a spam, o pasan algunos', tono: 'medio', onoma: 'BZZT' },
  facil: { titulo: 'Fácil de suplantar', sub: 'Nada frena un correo falso', tono: 'rojo', onoma: 'CRAC' },
};

export function decidirVeredicto(h, dmarc, spf) {
  const p = dmarc.politica;
  const nulo = !h.recibeCorreo && spf.puntos >= 25 && h.spf.parseado?.all === '-' && !h.spf.parseado.mecanismos.some((m) => m.tipo !== 'all');
  if (p === 'reject' && dmarc.pct === 100 && nulo) return 'blindado';
  if (!p || p === 'none') return 'facil';
  if (p === 'quarantine' || dmarc.pct < 100) return 'a-medias';
  if (dmarc.sp === 'none' || spf.estado === 'mal') return 'dificil';
  return 'muy-dificil';
}

/** Todo junto: { puntos, nota, veredicto, tarjetas, tope }. */
export function puntuar(h) {
  const spf = puntuarSPF(h);
  const dmarc = puntuarDMARC(h);
  const veredictoPrevio = decidirVeredicto(h, dmarc, spf);
  const dkim = puntuarDKIM(h, { sinCorreoBlindado: veredictoPrevio === 'blindado' });
  const extras = puntuarExtras(h);
  const mx = tarjetaMX(h);
  const tarjetas = [dmarc, spf, dkim, mx, ...extras];
  let puntos = redondear(tarjetas.reduce((a, t) => a + t.puntos, 0));
  let tope = false;
  if ((!dmarc.politica || dmarc.politica === 'none') && puntos > TOPE_SIN_DMARC) { puntos = TOPE_SIN_DMARC; tope = true; }
  const veredicto = veredictoPrevio;
  return { puntos, nota: notaDe(puntos), veredicto, ...VEREDICTOS[veredicto], tarjetas, tope };
}
