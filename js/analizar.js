// Reúne los hechos DNS de un dominio con un resolutor (en vivo o guardado). No puntúa: eso es puntuar.js.
import { textos, registrosMX } from './dns.js';
import { dominioOrganizacional } from './dominio.js';
import { buscarSPF, parsearSPF, contarBusquedas, proveedorDeMX } from './spf.js';
import { buscarDMARC, parsearDMARC } from './dmarc.js';
import { SELECTORES, esDKIM, analizarDKIM, buscarMTASTS, buscarTLSRPT, buscarBIMI } from './dkim.js';

/** Envuelve una consulta para que un fallo no tumbe todo: devuelve { ok, r } o { ok: false, error }. */
async function intentar(p) {
  try { return { ok: true, r: await p }; } catch (e) { return { ok: false, error: e.message }; }
}

/**
 * hechos = { dominio, organizacional, existe, dnssec, mx, nullMX, recibeCorreo, proveedor,
 *            spf, dmarc, dkim, mtasts, tlsrpt, bimi, fallos }
 */
export async function analizar(dominio, resolver, { selectores = SELECTORES } = {}) {
  const org = dominioOrganizacional(dominio);
  const fallos = [];
  const txt = async (nombre) => {
    const r = await resolver(nombre, 'TXT');
    return { estado: r.estado, ad: r.ad, txts: textos(r) };
  };

  const [rMX, rTXT, rDMARC, rSTS, rRPT, rBIMI, ...rDKIM] = await Promise.all([
    intentar(resolver(dominio, 'MX')),
    intentar(txt(dominio)),
    intentar(txt(`_dmarc.${dominio}`)),
    intentar(txt(`_mta-sts.${dominio}`)),
    intentar(txt(`_smtp._tls.${dominio}`)),
    intentar(txt(`default._bimi.${dominio}`)),
    ...selectores.map((s) => intentar(txt(`${s}._domainkey.${dominio}`))),
  ]);

  if (!rMX.ok && !rTXT.ok) {
    throw new Error(`No se pudo consultar el DNS: ${rTXT.error}`);
  }
  for (const [nombre, x] of [['MX', rMX], ['TXT', rTXT], ['DMARC', rDMARC]]) if (!x.ok) fallos.push(`${nombre}: ${x.error}`);

  // ¿Existe? NXDOMAIN en la consulta principal = el nombre no está registrado (o no tiene ningún registro).
  const estadoBase = rTXT.ok ? rTXT.r.estado : rMX.r.estado;
  const existe = estadoBase !== 3;
  const dnssec = Boolean((rMX.ok && rMX.r.ad) || (rTXT.ok && rTXT.r.ad));

  // MX
  const mx = rMX.ok ? registrosMX(rMX.r) : [];
  const nullMX = mx.length === 1 && mx[0].host === '';
  const recibeCorreo = mx.length > 0 && !nullMX;
  const proveedor = proveedorDeMX(mx);

  // SPF
  const registrosSPF = rTXT.ok ? buscarSPF(rTXT.r.txts) : [];
  let spf = { registros: registrosSPF, parseado: null, busquedas: null, consultado: rTXT.ok };
  if (registrosSPF.length >= 1) {
    spf.parseado = parsearSPF(registrosSPF[0]);
    const obtener = (nombre) => (nombre === dominio ? Promise.resolve({ estado: 0, txts: registrosSPF }) : txt(nombre));
    spf.busquedas = await contarBusquedas(dominio, obtener);
  }

  // DMARC: primero el nombre exacto; si no hay, el dominio organizacional (y ahí cuenta sp).
  let dmarc = { registro: null, registros: [], origen: null, consultado: rDMARC.ok, parseado: null };
  const regsExacto = rDMARC.ok ? buscarDMARC(rDMARC.r.txts) : [];
  if (regsExacto.length) {
    dmarc = { ...dmarc, registros: regsExacto, registro: regsExacto[0], origen: 'exacto', nombre: `_dmarc.${dominio}` };
  } else if (org !== dominio) {
    const rOrg = await intentar(txt(`_dmarc.${org}`));
    const regsOrg = rOrg.ok ? buscarDMARC(rOrg.r.txts) : [];
    if (regsOrg.length) dmarc = { ...dmarc, registros: regsOrg, registro: regsOrg[0], origen: 'organizacional', nombre: `_dmarc.${org}` };
  }
  if (dmarc.registro) {
    dmarc.parseado = parsearDMARC(dmarc.registro);
    if (dmarc.registros.length > 1) dmarc.parseado.errores.push(`hay ${dmarc.registros.length} registros DMARC: con más de uno no se aplica ninguno`);
  }

  // DKIM
  const encontrados = [];
  rDKIM.forEach((x, i) => {
    if (!x.ok) return;
    const clave = x.r.txts.find(esDKIM);
    if (clave) encontrados.push({ selector: selectores[i], ...analizarDKIM(clave) });
  });
  const dkim = { probados: selectores.length, encontrados, fallidos: rDKIM.filter((x) => !x.ok).length };

  const primero = (x, f) => (x.ok ? f(x.r.txts)[0] ?? null : null);
  return {
    dominio,
    organizacional: org,
    existe,
    dnssec,
    mx,
    nullMX,
    recibeCorreo,
    proveedor: proveedor ? { nombre: proveedor.nombre, include: proveedor.include, dkim: proveedor.dkim } : null,
    spf,
    dmarc,
    dkim,
    mtasts: primero(rSTS, buscarMTASTS),
    tlsrpt: primero(rRPT, buscarTLSRPT),
    bimi: primero(rBIMI, buscarBIMI),
    fallos,
  };
}
