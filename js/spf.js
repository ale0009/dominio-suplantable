// SPF (RFC 7208): leer el registro, contar búsquedas DNS siguiendo los include y proponer un arreglo.

export const LIMITE_BUSQUEDAS = 10;   // RFC 7208, 4.6.4
export const LIMITE_VACIAS = 2;       // RFC 7208, 4.6.4 (búsquedas que no devuelven nada)
const CON_BUSQUEDA = new Set(['include', 'a', 'mx', 'ptr', 'exists']);
const MECANISMOS = new Set(['all', 'include', 'a', 'mx', 'ptr', 'ip4', 'ip6', 'exists']);
const CALIFICADORES = new Set(['+', '-', '~', '?']);

/** De todos los TXT de un nombre, los que son SPF (empiezan por «v=spf1», sin distinguir mayúsculas). */
export function buscarSPF(txts) {
  return txts.filter((t) => /^v=spf1(\s|$)/i.test(t.trim()));
}

/**
 * Parte un registro SPF en mecanismos y modificadores.
 * Devuelve { mecanismos: [{ calificador, tipo, valor, texto }], redirect, exp, all, desconocidos, macros }.
 */
export function parsearSPF(registro) {
  const terminos = registro.trim().split(/\s+/).slice(1);
  const out = { mecanismos: [], redirect: null, exp: null, all: null, desconocidos: [], macros: [] };
  for (const texto of terminos) {
    const mod = /^([a-z][a-z0-9_.-]*)=(.*)$/i.exec(texto);
    if (mod) {
      const nombre = mod[1].toLowerCase();
      if (nombre === 'redirect') out.redirect = mod[2];
      else if (nombre === 'exp') out.exp = mod[2];
      else out.desconocidos.push(texto);
      if (mod[2].includes('%{')) out.macros.push(texto);
      continue;
    }
    let calificador = '+';
    let resto = texto;
    if (CALIFICADORES.has(resto[0])) { calificador = resto[0]; resto = resto.slice(1); }
    const m = /^([a-z0-9]+)(?:[:/](.*))?$/i.exec(resto);
    const tipo = m?.[1].toLowerCase();
    if (!m || !MECANISMOS.has(tipo)) { out.desconocidos.push(texto); continue; }
    const valor = resto.includes(':') ? resto.slice(resto.indexOf(':') + 1) : null;
    const mec = { calificador, tipo, valor, texto };
    out.mecanismos.push(mec);
    if (valor?.includes('%{')) out.macros.push(texto);
    if (tipo === 'all' && !out.all) out.all = calificador;
  }
  return out;
}

/** Cuántas búsquedas DNS cuesta este registro por sí solo (sin seguir los include). */
export function busquedasPropias(p) {
  return p.mecanismos.filter((m) => CON_BUSQUEDA.has(m.tipo)).length + (p.redirect && !p.all ? 1 : 0);
}

/**
 * Recorre el árbol de include/redirect con `obtenerTXT(nombre) → Promise<{ estado, txts }>`.
 * Devuelve { total, vacias, nodos: [{ dominio, profundidad, propias, error }], errores, macros, ptr }.
 */
export async function contarBusquedas(dominio, obtenerTXT, { profundidadMax = 10 } = {}) {
  const res = { total: 0, vacias: 0, nodos: [], errores: [], macros: [], ptr: false };
  const visitados = new Set();

  async function visitar(nombre, profundidad, registro) {
    const clave = nombre.toLowerCase();
    if (visitados.has(clave)) { res.errores.push(`bucle: ${nombre} ya se había incluido`); return; }
    visitados.add(clave);
    if (profundidad > profundidadMax) { res.errores.push(`demasiados niveles en ${nombre}`); return; }
    let reg = registro;
    if (reg == null) {
      let r;
      try {
        r = await obtenerTXT(nombre);
      } catch (e) {
        res.errores.push(`no se pudo leer ${nombre}: ${e.message}`);
        res.nodos.push({ dominio: nombre, profundidad, propias: 0, error: 'sin respuesta' });
        return;
      }
      const spfs = buscarSPF(r.txts);
      if (r.estado === 3 || spfs.length === 0) {
        res.vacias += r.estado === 3 || r.txts.length === 0 ? 1 : 0;
        res.errores.push(`${nombre} no tiene SPF (el include falla: permerror)`);
        res.nodos.push({ dominio: nombre, profundidad, propias: 0, error: 'sin SPF' });
        return;
      }
      if (spfs.length > 1) res.errores.push(`${nombre} tiene ${spfs.length} registros SPF (permerror)`);
      reg = spfs[0];
    }
    const p = parsearSPF(reg);
    const propias = busquedasPropias(p);
    res.total += propias;
    res.nodos.push({ dominio: nombre, profundidad, propias, error: null });
    if (p.mecanismos.some((m) => m.tipo === 'ptr')) res.ptr = true;
    res.macros.push(...p.macros);
    const hijos = p.mecanismos.filter((m) => m.tipo === 'include' && m.valor && !m.valor.includes('%{')).map((m) => m.valor);
    if (p.redirect && !p.all && !p.redirect.includes('%{')) hijos.push(p.redirect);
    // En paralelo: el orden de los nodos no importa para el total.
    await Promise.all(hijos.map((h) => visitar(h, profundidad + 1, null)));
  }

  await visitar(dominio, 0, null);
  return res;
}

/** Proveedor de correo deducido de los MX, con el include SPF que publica cada uno. */
export const PROVEEDORES_CORREO = [
  { patron: /(^|\.)google(mail)?\.com$|(^|\.)googlemail\.com$/, nombre: 'Google Workspace', include: 'include:_spf.google.com', dkim: 'google' },
  { patron: /\.mail\.protection\.outlook\.com$|\.outlook\.com$/, nombre: 'Microsoft 365', include: 'include:spf.protection.outlook.com', dkim: 'selector1' },
  { patron: /(^|\.)zoho(mail)?\.(com|eu|in)$/, nombre: 'Zoho Mail', include: 'include:zohomail.com', dkim: 'zmail' },
  { patron: /(^|\.)protonmail\.ch$/, nombre: 'Proton Mail', include: 'include:_spf.protonmail.ch', dkim: 'protonmail' },
  { patron: /(^|\.)messagingengine\.com$/, nombre: 'Fastmail', include: 'include:spf.messagingengine.com', dkim: 'fm1' },
  { patron: /(^|\.)secureserver\.net$/, nombre: 'GoDaddy', include: 'include:secureserver.net', dkim: 'default' },
];

export function proveedorDeMX(mx) {
  for (const { host } of mx) {
    const p = PROVEEDORES_CORREO.find((x) => x.patron.test(host));
    if (p) return p;
  }
  return null;
}

/**
 * Registro SPF recomendado.
 * - Sin correo: el SPF nulo «v=spf1 -all».
 * - Sin SPF: el include del proveedor (o «mx») con ~all.
 * - Varios SPF: se funden en uno.
 * - Con +all, ?all o sin all: se cambia el final a ~all.
 */
export function recomendarSPF({ registros, recibeCorreo, proveedor }) {
  if (!recibeCorreo && registros.length === 0) return 'v=spf1 -all';
  if (registros.length === 0) return `v=spf1 ${proveedor ? proveedor.include : 'mx'} ~all`;
  const vistos = new Set();
  const terminos = [];
  for (const r of registros) {
    const p = parsearSPF(r);
    for (const m of p.mecanismos) {
      if (m.tipo === 'all') continue;
      const t = m.texto.replace(/^\+/, '');
      if (!vistos.has(t.toLowerCase())) { vistos.add(t.toLowerCase()); terminos.push(t); }
    }
  }
  const actual = parsearSPF(registros[0]);
  if (registros.length === 1 && actual.redirect && !actual.all) return registros[0].trim();
  const fin = registros.length === 1 && (actual.all === '-' || actual.all === '~') ? `${actual.all}all` : '~all';
  if (terminos.length === 0 && !recibeCorreo) return 'v=spf1 -all';
  return ['v=spf1', ...terminos, fin].join(' ');
}
