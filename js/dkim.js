// DKIM (RFC 6376) y registros extra: MTA-STS (RFC 8461), TLS-RPT (RFC 8460) y BIMI.

// DKIM no se puede enumerar: la clave vive en <selector>._domainkey.<dominio> y el selector lo elige
// cada proveedor. Se prueban los más comunes; si ninguno responde, «no encontrado» no quiere decir «no tiene».
export const SELECTORES = [
  'google', 'selector1', 'selector2', 'default', 'k1', 'k2', 's1', 's2', 'mail', 'dkim',
  'zoho', 'zmail', 'mxvault', 'smtp', 'key1', 'sig1', 'fm1', 'protonmail', 'mandrill', 'everlytickey1',
];

/** ¿Este TXT es una clave DKIM? (v=DKIM1 es opcional, pero p= es obligatorio). */
export function esDKIM(txt) {
  return /(^|;)\s*p\s*=/i.test(txt) && (!/^\s*v\s*=/i.test(txt) || /^\s*v\s*=\s*DKIM1\s*(;|$)/i.test(txt));
}

/** Etiquetas «a=b; c=d» de DKIM, MTA-STS, TLS-RPT o BIMI. */
export function etiquetas(txt) {
  const out = {};
  for (const par of txt.split(';')) {
    const k = par.indexOf('=');
    if (k < 1) continue;
    out[par.slice(0, k).trim().toLowerCase()] = par.slice(k + 1).replace(/\s+/g, '');
  }
  return out;
}

function base64ABytes(b64) {
  const limpio = b64.replace(/[^A-Za-z0-9+/=]/g, '');
  const bin = atob(limpio);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i += 1) bytes[i] = bin.charCodeAt(i);
  return bytes;
}

// Lector DER mínimo: solo lo necesario para llegar al módulo RSA.
function leerTLV(b, i) {
  const tag = b[i];
  let len = b[i + 1];
  let ini = i + 2;
  if (len & 0x80) {
    const n = len & 0x7f;
    len = 0;
    for (let k = 0; k < n; k += 1) len = len * 256 + b[ini + k];
    ini += n;
  }
  if (ini + len > b.length) throw new Error('DER truncado');
  return { tag, ini, fin: ini + len };
}

/** Bits del módulo RSA de una clave pública en base64 (SubjectPublicKeyInfo o RSAPublicKey). null si no se puede leer. */
export function bitsRSA(p64) {
  try {
    let b = base64ABytes(p64);
    let s = leerTLV(b, 0);
    if (s.tag !== 0x30) return null;
    let x = leerTLV(b, s.ini);
    if (x.tag === 0x30) { // SubjectPublicKeyInfo: { algoritmo, BIT STRING { RSAPublicKey } }
      const bs = leerTLV(b, x.fin);
      if (bs.tag !== 0x03) return null;
      b = b.subarray(bs.ini + 1, bs.fin);
      s = leerTLV(b, 0);
      x = leerTLV(b, s.ini);
    }
    if (x.tag !== 0x02) return null;
    let ini = x.ini;
    while (ini < x.fin && b[ini] === 0) ini += 1; // el 0x00 inicial del entero positivo
    if (ini >= x.fin) return null;
    let bits = (x.fin - ini) * 8;
    for (let m = 0x80; m && !(b[ini] & m); m >>= 1) bits -= 1;
    return bits;
  } catch {
    return null;
  }
}

/** Resume una clave DKIM: { tipo, bits, revocada, prueba }. */
export function analizarDKIM(txt) {
  const t = etiquetas(txt);
  const tipo = (t.k || 'rsa').toLowerCase();
  const revocada = !t.p;
  let bits = null;
  if (!revocada) bits = tipo === 'ed25519' ? 256 : bitsRSA(t.p);
  return { tipo, bits, revocada, prueba: /(^|:)y(:|$)/i.test(t.t || '') };
}

/** ¿La clave es fuerte? ed25519 o RSA ≥ 2048 (RFC 8301 prohíbe < 1024; 2048 es lo recomendado). */
export function fuerzaDKIM(c) {
  if (c.revocada) return 'revocada';
  if (c.tipo === 'ed25519') return 'fuerte';
  if (c.bits == null) return 'desconocida';
  if (c.bits >= 2048) return 'fuerte';
  if (c.bits >= 1024) return 'aceptable';
  return 'debil';
}

export const buscarMTASTS = (txts) => txts.filter((t) => /^v=STSv1\s*;/i.test(t.trim()));
export const buscarTLSRPT = (txts) => txts.filter((t) => /^v=TLSRPTv1\s*;/i.test(t.trim()));
export const buscarBIMI = (txts) => txts.filter((t) => /^v=BIMI1\s*(;|$)/i.test(t.trim()));
