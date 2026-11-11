// Normalizar lo que escribe la persona y hallar el «dominio organizacional» (RFC 7489, sección 3.2).

// Sufijos públicos de segundo nivel más comunes. No es la Public Suffix List completa: es una
// aproximación suficiente para Colombia y los casos frecuentes (limitación explicada en /proceso/).
const SUFIJOS_2 = new Set([
  'com.co', 'edu.co', 'gov.co', 'org.co', 'net.co', 'mil.co', 'nom.co',
  'com.mx', 'edu.mx', 'gob.mx', 'org.mx', 'com.ar', 'gob.ar', 'edu.ar', 'org.ar',
  'com.br', 'gov.br', 'edu.br', 'org.br', 'com.pe', 'gob.pe', 'edu.pe', 'com.ec', 'gob.ec', 'edu.ec',
  'gob.cl', 'com.ve', 'gob.ve', 'com.es', 'org.es', 'gob.es', 'edu.es',
  'co.uk', 'ac.uk', 'gov.uk', 'org.uk', 'com.au', 'edu.au', 'gov.au',
]);

const ETIQUETA = /^(?!-)[a-z0-9-]{1,63}(?<!-)$/;

/**
 * Convierte «https://www.Ejemplo.com.co/ruta», «ana@ejemplo.co» o «ejemplo.co.» en «ejemplo.com.co».
 * Devuelve { dominio, quitoWww } o lanza un Error con un mensaje claro.
 */
export function normalizarDominio(entrada) {
  let s = String(entrada ?? '').trim().toLowerCase();
  if (!s) throw new Error('Escribe un dominio, por ejemplo ejemplo.com.co.');
  if (s.includes('@')) s = s.slice(s.lastIndexOf('@') + 1);
  s = s.replace(/^[a-z][a-z0-9+.-]*:\/\//, '');
  s = s.split(/[/?#]/)[0].replace(/:\d+$/, '').replace(/\.$/, '');
  let host;
  try {
    host = new URL(`http://${s}`).hostname; // convierte nombres con tildes a punycode (xn--)
  } catch {
    throw new Error(`«${String(entrada).trim()}» no parece un dominio.`);
  }
  let quitoWww = false;
  if (host.startsWith('www.') && host.split('.').length > 2) { host = host.slice(4); quitoWww = true; }
  const partes = host.split('.');
  if (partes.length < 2 || !partes.every((p) => ETIQUETA.test(p)) || /^\d+$/.test(partes.at(-1))) {
    throw new Error(`«${String(entrada).trim()}» no parece un dominio (falta el punto o hay caracteres raros).`);
  }
  if (host.length > 253) throw new Error('El dominio es demasiado largo (máximo 253 caracteres).');
  return { dominio: host, quitoWww };
}

/** Dominio organizacional aproximado: «correo.unal.edu.co» → «unal.edu.co»; «mail.google.com» → «google.com». */
export function dominioOrganizacional(dominio) {
  const p = dominio.split('.');
  if (p.length <= 2) return dominio;
  const dos = p.slice(-2).join('.');
  return SUFIJOS_2.has(dos) ? p.slice(-3).join('.') : dos;
}

/** ¿El nombre es en sí un sufijo público (gov.co, edu.co…)? Ahí no tiene sentido buscar correo de nadie. */
export function esSufijoPublico(dominio) {
  return SUFIJOS_2.has(dominio);
}
