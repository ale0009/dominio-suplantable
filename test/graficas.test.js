import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { barrasApiladas, barraPesos, CATEGORIAS_DMARC } from '../js/graficas.js';
import { PESOS } from '../js/puntuar.js';

test('barras apiladas: un segmento por categoría con datos y anchos proporcionales', () => {
  const svg = barrasApiladas([{ rotulo: 'A & B', conteos: { none: 1, reject: 3 } }], CATEGORIAS_DMARC, { ancho: 410, margenIzq: 0 });
  assert.equal((svg.match(/<rect/g) || []).length, 2);
  assert.match(svg, /width="100\.0"/); // 1 de 4 sobre 400 px útiles
  assert.match(svg, /width="300\.0"/);
  assert.match(svg, /A &amp; B/);
});

test('el estudio guardado suma lo mismo por política que por grupo', () => {
  const e = JSON.parse(readFileSync(new URL('../datos/estudio-2026-11-10.json', import.meta.url), 'utf8'));
  const suma = (o) => Object.values(o).reduce((a, b) => a + b, 0);
  assert.equal(suma(e.total.dmarc), e.total.n);
  assert.equal(e.gov.n + e.edu.n, e.total.n);
  for (const c of CATEGORIAS_DMARC) assert.equal((e.gov.dmarc[c.id] ?? 0) + (e.edu.dmarc[c.id] ?? 0), e.total.dmarc[c.id] ?? 0);
  const svg = barraPesos(Object.entries(PESOS).map(([nombre, puntos]) => ({ nombre, puntos, color: 'red' })));
  assert.equal((svg.match(/<rect/g) || []).length, Object.keys(PESOS).length);
});
