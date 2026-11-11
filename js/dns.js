// DNS sobre HTTPS (DoH) en formato JSON: Google Public DNS y Cloudflare. Ambos responden con CORS «*».
// Todo lo que sale de aquí es una respuesta normalizada: { estado, ad, respuestas: [{ tipo, datos }] }.

export const TIPOS = { A: 1, CNAME: 5, SOA: 6, MX: 15, TXT: 16, AAAA: 28, DS: 43 };
export const ESTADOS_DNS = { 0: 'NOERROR', 1: 'FORMERR', 2: 'SERVFAIL', 3: 'NXDOMAIN', 5: 'REFUSED' };

export const PROVEEDORES = {
  google: { nombre: 'Google Public DNS', url: 'https://dns.google/resolve' },
  cloudflare: { nombre: 'Cloudflare', url: 'https://cloudflare-dns.com/dns-query' },
};

export function urlDoH(proveedor, nombre, tipo) {
  const p = PROVEEDORES[proveedor];
  if (!p) throw new Error(`Proveedor DoH desconocido: ${proveedor}`);
  return `${p.url}?name=${encodeURIComponent(nombre)}&type=${encodeURIComponent(tipo)}`;
}

/**
 * Texto de un registro TXT. Cloudflare lo entrega con comillas y partido en trozos de 255
 * («"v=DKIM1; p=MIIB" "IjAN…"»); Google ya lo entrega unido y sin comillas. Aquí quedan iguales.
 */
export function textoTXT(datos) {
  const s = String(datos ?? '').trim();
  if (!s.startsWith('"')) return s;
  let out = '';
  const re = /"((?:[^"\\]|\\.)*)"/g;
  let m;
  while ((m = re.exec(s))) out += m[1].replace(/\\(\d{3})/g, (_, d) => String.fromCharCode(Number(d))).replace(/\\(.)/g, '$1');
  return out;
}

/** Pasa la respuesta JSON cruda de cualquiera de los dos proveedores al formato común. */
export function normalizarRespuesta(json) {
  if (!json || typeof json.Status !== 'number') throw new Error('Respuesta DoH sin el campo Status');
  const respuestas = (json.Answer ?? []).map((a) => ({
    nombre: String(a.name).replace(/\.$/, '').toLowerCase(),
    tipo: a.type,
    datos: a.type === TIPOS.TXT ? textoTXT(a.data) : String(a.data),
  }));
  return { estado: json.Status, ad: Boolean(json.AD), respuestas };
}

/** Solo los TXT (descarta los CNAME que aparecen cuando el nombre es un alias). */
export const textos = (r) => r.respuestas.filter((a) => a.tipo === TIPOS.TXT).map((a) => a.datos);

/** MX como [{ preferencia, host }], ordenados. «0 .» es el MX nulo (RFC 7505): el dominio no recibe correo. */
export function registrosMX(r) {
  return r.respuestas.filter((a) => a.tipo === TIPOS.MX).map((a) => {
    const [pref, host = ''] = a.datos.trim().split(/\s+/);
    return { preferencia: Number(pref), host: host.replace(/\.$/, '').toLowerCase() };
  }).sort((a, b) => a.preferencia - b.preferencia || a.host.localeCompare(b.host));
}

const clave = (nombre, tipo) => `${String(nombre).toLowerCase().replace(/\.$/, '')}|${String(tipo).toUpperCase()}`;

function explicar(err, quien, limite) {
  if (err?.name === 'AbortError') return `${quien} tardó más de ${Math.round(limite / 1000)} s`;
  if (err?.estado) return `${quien} respondió con el código HTTP ${err.estado}`;
  if (err instanceof TypeError) return `no se pudo llegar a ${quien} (sin conexión o bloqueado)`;
  return `${quien}: ${err?.message || 'error desconocido'}`;
}

/**
 * Resolutor en vivo. Prueba los proveedores en orden y pasa al siguiente si uno falla.
 * `guardar(clave, json)` permite grabar las respuestas crudas (para las pruebas y el modo sin conexión).
 */
export function crearResolutorDoH({ fetch: f = globalThis.fetch, orden = ['google', 'cloudflare'], limite = 8000, guardar } = {}) {
  const cache = new Map();
  const usados = new Set();
  const errores = [];
  async function pedir(proveedor, nombre, tipo) {
    const ctl = new AbortController();
    const t = setTimeout(() => ctl.abort(), limite);
    try {
      const r = await f(urlDoH(proveedor, nombre, tipo), { signal: ctl.signal, headers: { accept: 'application/dns-json' } });
      if (!r.ok) throw Object.assign(new Error(`HTTP ${r.status}`), { estado: r.status });
      return await r.json();
    } catch (e) {
      throw new Error(explicar(e, PROVEEDORES[proveedor].nombre, limite));
    } finally {
      clearTimeout(t);
    }
  }
  async function resolver(nombre, tipo) {
    const k = clave(nombre, tipo);
    if (!cache.has(k)) {
      cache.set(k, (async () => {
        const fallos = [];
        for (const p of orden) {
          try {
            const json = await pedir(p, nombre, tipo);
            const norm = normalizarRespuesta(json);
            if (norm.estado === 2 && p !== orden.at(-1)) { fallos.push(`${PROVEEDORES[p].nombre}: SERVFAIL`); continue; }
            usados.add(p);
            guardar?.(k, json);
            return norm;
          } catch (e) {
            fallos.push(e.message);
          }
        }
        errores.push(...fallos);
        cache.delete(k);
        throw new Error(fallos.join(' · '));
      })());
    }
    return cache.get(k);
  }
  resolver.usados = usados;
  resolver.errores = errores;
  return resolver;
}

/**
 * Resolutor desde respuestas guardadas ({ "nombre|TIPO": json crudo }). Lo usan las pruebas
 * y el modo sin conexión. Si una pregunta no está guardada, responde «no existe» o falla.
 */
export function crearResolutorGuardado(mapa, { estricto = false } = {}) {
  async function resolver(nombre, tipo) {
    const k = clave(nombre, tipo);
    if (k in mapa) return normalizarRespuesta(mapa[k]);
    if (estricto) throw new Error(`Sin respuesta guardada para ${k}`);
    return { estado: 3, ad: false, respuestas: [] };
  }
  resolver.usados = new Set(['guardado']);
  resolver.errores = [];
  return resolver;
}

export { clave as claveDNS };
