// Muestra: la misma lógica de la página sobre 30 dominios públicos colombianos (.gov.co y .edu.co).
// Publica solo los totales (datos/estudio-AAAA-MM-DD.json); el detalle por dominio queda en fuente/ (no se versiona).
// Uso: node scripts/estudio.mjs
import { writeFileSync, mkdirSync } from 'node:fs';
import { crearResolutorDoH } from '../js/dns.js';
import { analizar } from '../js/analizar.js';
import { puntuar } from '../js/puntuar.js';

export const MUESTRA = {
  gov: [
    'presidencia.gov.co', 'minhacienda.gov.co', 'mintic.gov.co', 'minsalud.gov.co', 'mineducacion.gov.co',
    'cancilleria.gov.co', 'dian.gov.co', 'registraduria.gov.co', 'policia.gov.co', 'fiscalia.gov.co',
    'sic.gov.co', 'dane.gov.co', 'supersociedades.gov.co', 'superfinanciera.gov.co', 'bogota.gov.co',
  ],
  edu: [
    'unal.edu.co', 'uniandes.edu.co', 'javeriana.edu.co', 'udea.edu.co', 'univalle.edu.co',
    'uis.edu.co', 'sena.edu.co', 'urosario.edu.co', 'ecci.edu.co', 'unab.edu.co',
    'eafit.edu.co', 'utp.edu.co', 'unicauca.edu.co', 'upn.edu.co', 'udistrital.edu.co',
  ],
};

const fecha = new Intl.DateTimeFormat('en-CA', { timeZone: 'America/Bogota' }).format(new Date()); // fecha de Colombia
const resolver = crearResolutorDoH({ limite: 10000 });
const filas = [];
for (const [grupo, lista] of Object.entries(MUESTRA)) {
  for (const d of lista) {
    try {
      const h = await analizar(d, resolver);
      const r = puntuar(h);
      const t = Object.fromEntries(r.tarjetas.map((x) => [x.id, x]));
      filas.push({
        grupo, dominio: d, existe: h.existe, recibeCorreo: h.recibeCorreo, nota: r.nota, puntos: r.puntos, veredicto: r.veredicto,
        dmarc: t.dmarc.politica ?? (h.dmarc.registro ? 'invalido' : 'sin'), pct: t.dmarc.pct ?? null, rua: Boolean(h.dmarc.parseado?.rua.length),
        spf: h.spf.registros.length === 0 ? 'sin' : h.spf.registros.length > 1 ? 'varios' : t.spf.etiqueta === 'Se rompe' ? 'roto' : `${h.spf.parseado.all ?? 'nada'}all`,
        busquedas: h.spf.busquedas?.total ?? null, dkim: h.dkim.encontrados.length > 0, dnssec: h.dnssec, mtasts: Boolean(h.mtasts),
      });
      console.log(`${d.padEnd(26)} ${r.nota} ${String(r.puntos).padStart(5)} ${filas.at(-1).dmarc.padEnd(10)} ${filas.at(-1).spf}`);
    } catch (e) {
      filas.push({ grupo, dominio: d, error: e.message });
      console.log(`${d.padEnd(26)} ERROR ${e.message}`);
    }
  }
}

const validas = filas.filter((f) => !f.error && f.existe);
const contar = (arr, k) => arr.reduce((o, f) => ({ ...o, [f[k]]: (o[f[k]] ?? 0) + 1 }), {});
const resumen = (arr) => ({
  n: arr.length,
  dmarc: contar(arr, 'dmarc'),
  dmarcParcial: arr.filter((f) => (f.dmarc === 'reject' || f.dmarc === 'quarantine') && f.pct < 100).length,
  spf: contar(arr, 'spf'),
  notas: contar(arr, 'nota'),
  veredictos: contar(arr, 'veredicto'),
  dkimEncontrado: arr.filter((f) => f.dkim).length,
  dnssec: arr.filter((f) => f.dnssec).length,
  mtasts: arr.filter((f) => f.mtasts).length,
  rua: arr.filter((f) => f.rua).length,
  spfRoto: arr.filter((f) => f.busquedas > 10).length,
});

const salida = {
  fecha,
  metodo: 'Lógica de esta página (js/analizar.js y js/puntuar.js) con DNS sobre HTTPS de Google y Cloudflare.',
  dominios: MUESTRA,
  sinDatos: filas.filter((f) => f.error || !f.existe).map((f) => f.dominio),
  total: resumen(validas),
  gov: resumen(validas.filter((f) => f.grupo === 'gov')),
  edu: resumen(validas.filter((f) => f.grupo === 'edu')),
};
writeFileSync(new URL(`../datos/estudio-${fecha}.json`, import.meta.url), `${JSON.stringify(salida, null, 1)}\n`);
mkdirSync(new URL('../fuente/', import.meta.url), { recursive: true });
writeFileSync(new URL(`../fuente/estudio-detalle-${fecha}.json`, import.meta.url), `${JSON.stringify(filas, null, 1)}\n`);
console.log(JSON.stringify(salida.total));
