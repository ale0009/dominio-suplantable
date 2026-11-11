// Página /proceso/: tema, reparto de puntos y muestra de 30 dominios colombianos.
import { iniciarTema } from './tema.js';
import { barrasApiladas, barraPesos, CATEGORIAS_DMARC } from './graficas.js';

const $ = (id) => document.getElementById(id);
const ESTUDIO = '../datos/estudio-2026-11-10.json';
const pct = (n, d) => `${Math.round((n / d) * 100)} %`;

function leyenda(nodo, items) {
  nodo.replaceChildren(...items.map((x) => {
    const li = document.createElement('li');
    const i = document.createElement('i');
    i.style.setProperty('--c', x.color);
    li.append(i, x.nombre);
    return li;
  }));
}

const PESOS = [
  { nombre: 'DMARC (política)', corto: 'DMARC', puntos: 40, color: 'var(--rojo)', texto: 'claro' },
  { nombre: 'DMARC (informes rua)', corto: 'rua', puntos: 5, color: 'var(--rojo-osc)', texto: 'claro' },
  { nombre: 'SPF', corto: 'SPF', puntos: 30, color: 'var(--cian)' },
  { nombre: 'DKIM', corto: 'DKIM', puntos: 15, color: 'var(--ambar)' },
  { nombre: 'DNSSEC, MTA-STS y TLS-RPT', corto: '+', puntos: 10, color: 'var(--papel-2)', texto: 'tinta' },
];

function pintarPesos() {
  $('g-pesos').innerHTML = barraPesos(PESOS);
  leyenda($('ley-pesos'), PESOS.map((p) => ({ color: p.color, nombre: `${p.nombre}: ${p.puntos}` })));
}

async function pintarMuestra() {
  try {
    const r = await fetch(ESTUDIO);
    if (!r.ok) throw new Error(`HTTP ${r.status}`);
    const e = await r.json();
    $('g-muestra').innerHTML = barrasApiladas([
      { rotulo: `.gov.co (${e.gov.n})`, conteos: e.gov.dmarc },
      { rotulo: `.edu.co (${e.edu.n})`, conteos: e.edu.dmarc },
      { rotulo: `Total (${e.total.n})`, conteos: e.total.dmarc },
    ]);
    leyenda($('ley-muestra'), CATEGORIAS_DMARC);
    $('muestra-pie').textContent = `Consulta del ${e.fecha} con DNS sobre HTTPS. Cada número es una cantidad de dominios. ${e.sinDatos.length ? `Sin datos: ${e.sinDatos.length}.` : 'Todos respondieron.'}`;
    const t = e.total;
    const d = (k) => t.dmarc[k] ?? 0;
    const facil = (t.veredictos.facil ?? 0);
    $('cifras').innerHTML = `<h3>Cifras (calculado aquí, ${t.n} dominios)</h3><ul>
      <li><strong>${d('reject')} de ${t.n}</strong> (${pct(d('reject'), t.n)}) tienen <code>p=reject</code>: ${e.gov.dmarc.reject ?? 0} .gov.co y ${e.edu.dmarc.reject ?? 0} .edu.co.</li>
      <li>${d('quarantine')} tienen <code>p=quarantine</code>; ${t.dmarcParcial} de los que aplican política lo hacen a menos del 100 % (<code>pct</code>).</li>
      <li><strong>${facil} de ${t.n}</strong> salen «fácil de suplantar» (${d('none')} con <code>p=none</code> y ${d('sin')} sin DMARC): ${e.gov.veredictos.facil ?? 0} .gov.co y ${e.edu.veredictos.facil ?? 0} .edu.co.</li>
      <li>SPF: ${t.spf['-all'] ?? 0} con <code>-all</code>, ${t.spf['~all'] ?? 0} con <code>~all</code>, ${t.spf.sin ?? 0} sin SPF${t.spfRoto ? `, ${t.spfRoto} roto por más de 10 búsquedas` : ''}.</li>
      <li>Clave DKIM encontrada con los selectores comunes: ${t.dkimEncontrado}. Informes rua: ${t.rua}. DNSSEC: ${t.dnssec}. MTA-STS: ${t.mtasts}.</li>
    </ul>`;
    $('lista-muestra').textContent = [...e.dominios.gov, ...e.dominios.edu].join(' · ');
  } catch (err) {
    $('g-muestra').innerHTML = '';
    const p = document.createElement('p');
    p.className = 'aviso';
    p.textContent = `No se pudo cargar la muestra (${err.message}). Los datos están en datos/estudio-2026-11-10.json.`;
    $('g-muestra').append(p);
    $('cifras').textContent = '';
  }
}

iniciarTema($('tema'));
pintarPesos();
pintarMuestra();
