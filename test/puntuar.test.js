// Pruebas de punta a punta (respuestas reales guardadas) y de la puntuación con casos construidos.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { crearResolutorGuardado } from '../js/dns.js';
import { analizar } from '../js/analizar.js';
import { puntuar, notaDe, PESOS, TOPE_SIN_DMARC } from '../js/puntuar.js';

const { respuestas } = JSON.parse(readFileSync(new URL('./muestras/respuestas-2026-11-10.json', import.meta.url), 'utf8'));
const guardado = crearResolutorGuardado(respuestas);
const tarjeta = (r, id) => r.tarjetas.find((t) => t.id === id);

/** Zona DNS inventada → resolutor con el mismo formato que DoH. */
function zona(registros) {
  const mapa = {};
  for (const [nombre, tipos] of Object.entries(registros)) {
    for (const [tipo, datos] of Object.entries(tipos)) {
      mapa[`${nombre}|${tipo}`] = { Status: 0, AD: Boolean(tipos.AD), Answer: datos.map((d) => ({ name: `${nombre}.`, type: tipo === 'MX' ? 15 : 16, data: d })) };
    }
  }
  return crearResolutorGuardado(mapa);
}

test('los pesos suman 100 y las notas van de A a F', () => {
  assert.equal(Object.values(PESOS).reduce((a, b) => a + b, 0), 100);
  assert.deepEqual([100, 90, 89.9, 75, 60, 59, 40, 39, 0].map(notaDe), ['A', 'A', 'B', 'B', 'C', 'D', 'D', 'F', 'F']);
});

test('paypal.com (real): reject al 100 % → muy difícil, nota A', async () => {
  const r = puntuar(await analizar('paypal.com', guardado));
  assert.equal(r.veredicto, 'muy-dificil');
  assert.equal(r.nota, 'A');
  assert.equal(tarjeta(r, 'dmarc').politica, 'reject');
  assert.equal(tarjeta(r, 'dnssec').estado, 'bien'); // paypal.com responde con la bandera AD
});

test('example.com (real): MX nulo + SPF nulo + reject → blindado', async () => {
  const h = await analizar('example.com', guardado);
  assert.equal(h.nullMX, true);
  assert.equal(h.recibeCorreo, false);
  const r = puntuar(h);
  assert.equal(r.veredicto, 'blindado');
  assert.equal(tarjeta(r, 'dkim').etiqueta, 'No aplica');
  assert.equal(tarjeta(r, 'dmarc').recomendado, null);
});

test('github.com (real): quarantine → suplantable a medias; DKIM fuerte; propone reject', async () => {
  const r = puntuar(await analizar('github.com', guardado));
  assert.equal(r.veredicto, 'a-medias');
  assert.equal(tarjeta(r, 'dkim').estado, 'bien');
  assert.match(tarjeta(r, 'dmarc').recomendado, /^v=DMARC1; p=reject;/);
  assert.equal(tarjeta(r, 'mtasts').recomendado, 'v=STSv1; id=20261110T000000');
});

test('python.org (real): p=none → fácil de suplantar, con tope de nota D', async () => {
  const r = puntuar(await analizar('python.org', guardado));
  assert.equal(r.veredicto, 'facil');
  assert.ok(r.puntos <= TOPE_SIN_DMARC);
  assert.equal(r.nota, 'D');
  assert.match(tarjeta(r, 'dmarc').recomendado, /p=quarantine/);
});

test('mozilla.org (real): SPF con macros se cuenta sin seguirlas', async () => {
  const h = await analizar('mozilla.org', guardado);
  assert.ok(h.spf.busquedas.macros.length >= 1);
  assert.ok(h.spf.busquedas.total <= 10);
  assert.equal(puntuar(h).veredicto, 'muy-dificil');
});

test('dominio sin nada: fácil de suplantar, F, y recomienda SPF y DMARC', async () => {
  const r = puntuar(await analizar('vacio.co', zona({ 'vacio.co': { TXT: ['google-site-verification=abc'], MX: ['10 smtp.google.com.'] } })));
  assert.equal(r.veredicto, 'facil');
  assert.equal(r.nota, 'F');
  assert.equal(tarjeta(r, 'spf').recomendado, 'v=spf1 include:_spf.google.com ~all');
  assert.equal(tarjeta(r, 'dmarc').recomendado, 'v=DMARC1; p=none; rua=mailto:dmarc@vacio.co');
});

test('dominio sin correo y sin registros: propone SPF nulo y DMARC reject', async () => {
  const r = puntuar(await analizar('quieto.co', zona({ 'quieto.co': { TXT: ['verificacion=1'], MX: [] } })));
  assert.equal(r.veredicto, 'facil');
  assert.equal(tarjeta(r, 'spf').recomendado, 'v=spf1 -all');
  assert.equal(tarjeta(r, 'dmarc').recomendado, 'v=DMARC1; p=reject; sp=reject; adkim=s; aspf=s');
});

test('SPF roto por exceso de búsquedas y dos SPF a la vez', async () => {
  const muchos = Array.from({ length: 11 }, (_, i) => `include:s${i}.co`).join(' ');
  const z = { 'roto.co': { TXT: [`v=spf1 ${muchos} -all`], MX: ['10 mx.roto.co.'] }, '_dmarc.roto.co': { TXT: ['v=DMARC1; p=reject; rua=mailto:d@roto.co'] } };
  for (let i = 0; i < 11; i += 1) z[`s${i}.co`] = { TXT: ['v=spf1 ip4:192.0.2.1 -all'] };
  const r = puntuar(await analizar('roto.co', zona(z)));
  assert.equal(tarjeta(r, 'spf').etiqueta, 'Se rompe');
  assert.equal(r.veredicto, 'dificil'); // DMARC rechaza, pero el SPF roto deja una rendija (y tumba correo legítimo)
  const dos = puntuar(await analizar('dos.co', zona({ 'dos.co': { TXT: ['v=spf1 mx -all', 'v=spf1 include:a.co ~all'], MX: ['1 mx.dos.co.'] } })));
  assert.equal(tarjeta(dos, 'spf').etiqueta, '2 registros');
  assert.equal(tarjeta(dos, 'spf').recomendado, 'v=spf1 mx include:a.co ~all');
});

test('pct parcial y sp=none bajan el veredicto y los puntos', async () => {
  const base = { 'p.co': { TXT: ['v=spf1 mx -all'], MX: ['1 mx.p.co.'] } };
  const parcial = puntuar(await analizar('p.co', zona({ ...base, '_dmarc.p.co': { TXT: ['v=DMARC1; p=reject; pct=20; rua=mailto:d@p.co'] } })));
  assert.equal(parcial.veredicto, 'a-medias');
  assert.equal(tarjeta(parcial, 'dmarc').puntos, 10 + 30 * 0.2 + 5);
  const sub = puntuar(await analizar('p.co', zona({ ...base, '_dmarc.p.co': { TXT: ['v=DMARC1; p=reject; sp=none; rua=mailto:d@p.co'] } })));
  assert.equal(sub.veredicto, 'dificil');
  assert.equal(tarjeta(sub, 'dmarc').puntos, 40);
});

test('subdominio sin DMARC propio hereda sp del dominio organizacional', async () => {
  const z = {
    'correo.uni.edu.co': { TXT: ['v=spf1 include:_spf.google.com ~all'], MX: ['1 smtp.google.com.'] },
    '_dmarc.uni.edu.co': { TXT: ['v=DMARC1; p=reject; sp=quarantine; rua=mailto:d@uni.edu.co'] },
  };
  const h = await analizar('correo.uni.edu.co', zona(z));
  assert.equal(h.organizacional, 'uni.edu.co');
  assert.equal(h.dmarc.origen, 'organizacional');
  const r = puntuar(h);
  assert.equal(tarjeta(r, 'dmarc').politica, 'quarantine');
  assert.equal(r.veredicto, 'a-medias');
  assert.equal(tarjeta(r, 'dmarc').recomendado, null);
});

test('dominio inexistente: existe = false', async () => {
  const h = await analizar('no-existe-zzqq.co', crearResolutorGuardado({}));
  assert.equal(h.existe, false);
});
