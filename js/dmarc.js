// DMARC (RFC 7489): leer las etiquetas, validar y armar el registro recomendado.

export const POLITICAS = ['none', 'quarantine', 'reject'];

/** Registros DMARC entre los TXT de _dmarc.<dominio> (deben empezar exactamente por «v=DMARC1»). */
export function buscarDMARC(txts) {
  return txts.filter((t) => /^v\s*=\s*DMARC1\s*(;|$)/i.test(t.trim()));
}

/**
 * Lee un registro DMARC. Devuelve { etiquetas, p, sp, pct, rua, ruf, adkim, aspf, errores, avisos }.
 * Los valores ausentes toman el valor por defecto de la RFC (sp = p, pct = 100, adkim = aspf = r).
 */
export function parsearDMARC(registro) {
  const etiquetas = {};
  const errores = [];
  const avisos = [];
  const partes = registro.split(';').map((x) => x.trim()).filter(Boolean);
  partes.forEach((par, i) => {
    const k = par.indexOf('=');
    if (k < 1) { avisos.push(`«${par}» no es una etiqueta (falta el =)`); return; }
    const nombre = par.slice(0, k).trim().toLowerCase();
    const valor = par.slice(k + 1).trim();
    if (i === 0 && (nombre !== 'v' || valor !== 'DMARC1')) errores.push('la primera etiqueta debe ser exactamente v=DMARC1');
    if (nombre in etiquetas) avisos.push(`la etiqueta ${nombre} está repetida`);
    else etiquetas[nombre] = valor;
  });
  const p = etiquetas.p?.toLowerCase();
  if (!p) errores.push('falta la política p (none, quarantine o reject)');
  else if (!POLITICAS.includes(p)) errores.push(`p=${etiquetas.p} no es válida (usa none, quarantine o reject)`);
  let sp = etiquetas.sp?.toLowerCase() ?? p;
  if (etiquetas.sp && !POLITICAS.includes(sp)) { avisos.push(`sp=${etiquetas.sp} no es válida; se usa la de p`); sp = p; }
  let pct = 100;
  if (etiquetas.pct != null) {
    const n = Number(etiquetas.pct);
    if (Number.isInteger(n) && n >= 0 && n <= 100) pct = n;
    else avisos.push(`pct=${etiquetas.pct} no es un entero de 0 a 100; se toma 100`);
  }
  const alineacion = (x, nombre) => {
    if (x == null) return 'r';
    const v = x.toLowerCase();
    if (v === 'r' || v === 's') return v;
    avisos.push(`${nombre}=${x} no es válida (r o s); se toma r`);
    return 'r';
  };
  const uris = (x) => (x ? x.split(',').map((u) => u.trim()).filter(Boolean) : []);
  const rua = uris(etiquetas.rua);
  const ruf = uris(etiquetas.ruf);
  for (const u of [...rua, ...ruf]) if (!/^mailto:[^@\s]+@[^@\s]+$/i.test(u.replace(/!\d+[kmgt]?$/i, ''))) avisos.push(`«${u}» no es una dirección mailto: válida`);
  return {
    etiquetas,
    p: POLITICAS.includes(p) ? p : null,
    sp: POLITICAS.includes(sp) ? sp : null,
    pct,
    rua,
    ruf,
    adkim: alineacion(etiquetas.adkim, 'adkim'),
    aspf: alineacion(etiquetas.aspf, 'aspf'),
    errores,
    avisos,
  };
}

/** La política que se aplica en la práctica: a un subdominio que hereda le toca sp. */
export function politicaEfectiva(d, { heredado = false } = {}) {
  if (!d || d.errores.length) return null;
  return heredado ? d.sp : d.p;
}

const ORDEN = ['v', 'p', 'sp', 'pct', 'rua', 'ruf', 'adkim', 'aspf', 'fo', 'rf', 'ri'];

/** Arma un registro DMARC con las etiquetas en el orden habitual. */
export function construirDMARC(etiquetas) {
  const ks = Object.keys(etiquetas).filter((k) => etiquetas[k] != null && etiquetas[k] !== '');
  ks.sort((a, b) => (ORDEN.indexOf(a) + 1 || 99) - (ORDEN.indexOf(b) + 1 || 99));
  return ks.map((k) => `${k}=${etiquetas[k]}`).join('; ');
}

/**
 * Siguiente paso recomendado (M3AAWG y CISA BOD 18-01: none → quarantine → reject, con informes rua).
 * - Sin correo: p=reject directo, alineación estricta.
 * - Sin DMARC: p=none con informes para empezar a ver quién envía en tu nombre.
 * - none → quarantine; quarantine o pct < 100 → reject al 100 %.
 */
export function recomendarDMARC({ dmarc, dominio, recibeCorreo }) {
  const informe = `mailto:dmarc@${dominio}`;
  const valido = dmarc && !dmarc.errores.length;
  if (!recibeCorreo && !(valido && dmarc.p === 'reject' && dmarc.pct === 100 && dmarc.sp === 'reject')) {
    return { registro: construirDMARC({ v: 'DMARC1', p: 'reject', sp: 'reject', adkim: 's', aspf: 's' }), paso: 'directo' };
  }
  if (!valido) {
    return { registro: construirDMARC({ v: 'DMARC1', p: 'none', rua: informe }), paso: 'empezar' };
  }
  const base = { ...dmarc.etiquetas, v: 'DMARC1' };
  if (!dmarc.rua.length) base.rua = informe;
  if (dmarc.p === 'none') {
    return { registro: construirDMARC({ ...base, p: 'quarantine', pct: null, sp: dmarc.sp === 'none' ? null : base.sp }), paso: 'subir' };
  }
  if (dmarc.p === 'quarantine' || dmarc.pct < 100 || dmarc.sp === 'none') {
    const sig = { ...base, p: 'reject', pct: null };
    if (dmarc.sp === 'none' || dmarc.sp === 'quarantine') sig.sp = null;
    return { registro: construirDMARC(sig), paso: 'subir' };
  }
  if (!recibeCorreo) return { registro: null, paso: 'listo' };
  return { registro: dmarc.rua.length ? null : construirDMARC(base), paso: dmarc.rua.length ? 'listo' : 'informes' };
}
