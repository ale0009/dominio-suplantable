// Gráficas SVG propias para /proceso/ (funciones puras: devuelven texto SVG).

export const CATEGORIAS_DMARC = [
  { id: 'sin', nombre: 'Sin DMARC', color: 'var(--rojo-osc)', texto: 'claro' },
  { id: 'none', nombre: 'p=none', color: 'var(--rojo)', texto: 'claro' },
  { id: 'quarantine', nombre: 'p=quarantine', color: 'var(--ambar)', texto: 'oscuro' },
  { id: 'reject', nombre: 'p=reject', color: 'var(--cian)', texto: 'oscuro' },
];

const esc = (s) => String(s).replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' })[c]);

/**
 * Barras apiladas horizontales. filas = [{ rotulo, conteos: { id: n } }].
 * Devuelve el SVG con una barra por fila y un segmento por categoría con n > 0.
 */
export function barrasApiladas(filas, categorias = CATEGORIAS_DMARC, { ancho = 640, alto = 34, margenIzq = 150 } = {}) {
  const sep = 14;
  const h = filas.length * (alto + sep) + 6;
  const util = ancho - margenIzq - 10;
  const partes = [];
  filas.forEach((f, i) => {
    const total = categorias.reduce((a, c) => a + (f.conteos[c.id] ?? 0), 0);
    const y = 3 + i * (alto + sep);
    partes.push(`<text class="g-rotulo" x="${margenIzq - 10}" y="${y + alto / 2 + 5}" text-anchor="end">${esc(f.rotulo)}</text>`);
    let x = margenIzq;
    for (const c of categorias) {
      const n = f.conteos[c.id] ?? 0;
      if (!n || !total) continue;
      const w = (n / total) * util;
      partes.push(`<g class="g-pila"><rect x="${x.toFixed(1)}" y="${y}" width="${w.toFixed(1)}" height="${alto}" style="fill:${c.color}"><title>${esc(f.rotulo)} · ${esc(c.nombre)}: ${n} de ${total}</title></rect>`
        + (w >= 22 ? `<text class="g-num ${c.texto}" x="${(x + w / 2).toFixed(1)}" y="${y + alto / 2 + 4}" text-anchor="middle">${n}</text>` : '')
        + '</g>');
      x += w;
    }
  });
  return `<svg class="grafica" viewBox="0 0 ${ancho} ${h}" role="img" aria-label="Barras apiladas por categoría">${partes.join('')}</svg>`;
}

/** Barra única con el reparto de los 100 puntos. pesos = [{ nombre, puntos, color }]. */
export function barraPesos(pesos, { ancho = 640, alto = 46 } = {}) {
  const total = pesos.reduce((a, p) => a + p.puntos, 0);
  let x = 0;
  const partes = pesos.map((p) => {
    const w = (p.puntos / total) * ancho;
    const g = `<g class="g-pila"><rect x="${x.toFixed(1)}" y="0" width="${w.toFixed(1)}" height="${alto}" style="fill:${p.color}"><title>${esc(p.nombre)}: ${p.puntos} puntos</title></rect>`
      + (w >= 46 ? `<text class="g-num ${p.texto ?? 'oscuro'}" x="${(x + w / 2).toFixed(1)}" y="${alto / 2 + 4}" text-anchor="middle">${esc(p.corto ?? p.nombre)} ${p.puntos}</text>` : '')
      + '</g>';
    x += w;
    return g;
  });
  return `<svg class="grafica" viewBox="0 0 ${ancho} ${alto}" role="img" aria-label="Reparto de los 100 puntos">${partes.join('')}</svg>`;
}
