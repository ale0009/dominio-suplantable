// Graba respuestas DoH reales para el modo sin conexión y para las pruebas.
// Uso: node scripts/capturar.mjs <salida.json> dominio1 dominio2 …
import { writeFileSync } from 'node:fs';
import { crearResolutorDoH } from '../js/dns.js';
import { analizar } from '../js/analizar.js';
import { puntuar } from '../js/puntuar.js';

const [salida, ...dominios] = process.argv.slice(2);
if (!salida || !dominios.length) {
  console.error('Uso: node scripts/capturar.mjs <salida.json> dominio…');
  process.exit(1);
}
const respuestas = {};
const resolver = crearResolutorDoH({ guardar: (k, json) => { respuestas[k] = json; } });
for (const d of dominios) {
  const h = await analizar(d, resolver);
  const r = puntuar(h);
  console.log(`${d.padEnd(28)} ${r.nota} ${String(r.puntos).padStart(5)}  ${r.veredicto}`);
}
const ahora = new Date();
writeFileSync(salida, `${JSON.stringify({
  capturado: ahora.toISOString(),
  fuente: [...resolver.usados].join(', '),
  dominios,
  respuestas: Object.fromEntries(Object.entries(respuestas).sort(([a], [b]) => a.localeCompare(b))),
}, null, 0)}\n`);
console.log(`${Object.keys(respuestas).length} respuestas en ${salida}`);
