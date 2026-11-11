// Pruebas de las funciones de lectura: dominio, DNS, SPF, DMARC y DKIM.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { normalizarDominio, dominioOrganizacional } from '../js/dominio.js';
import { textoTXT, normalizarRespuesta, textos, registrosMX, urlDoH, crearResolutorDoH } from '../js/dns.js';
import { buscarSPF, parsearSPF, busquedasPropias, contarBusquedas, recomendarSPF, proveedorDeMX } from '../js/spf.js';
import { buscarDMARC, parsearDMARC, construirDMARC, recomendarDMARC } from '../js/dmarc.js';
import { esDKIM, analizarDKIM, bitsRSA, fuerzaDKIM } from '../js/dkim.js';

const leer = (f) => JSON.parse(readFileSync(new URL(`./muestras/${f}`, import.meta.url), 'utf8'));
// Respuestas reales de dns.google grabadas el 10 nov 2026 con scripts/capturar.mjs.
const { respuestas } = leer('respuestas-2026-11-10.json');
const real = (k) => normalizarRespuesta(respuestas[k]);

test('normalizar: URL, correo, mayúsculas, www y punto final', () => {
  assert.deepEqual(normalizarDominio('https://www.PayPal.com/co/home?x=1'), { dominio: 'paypal.com', quitoWww: true });
  assert.equal(normalizarDominio('ana.perez@Ejemplo.edu.co').dominio, 'ejemplo.edu.co');
  assert.equal(normalizarDominio(' ejemplo.co. ').dominio, 'ejemplo.co');
  assert.equal(normalizarDominio('www.co').dominio, 'www.co'); // no deja el TLD solo
  assert.match(normalizarDominio('añoñuevo.co').dominio, /^xn--[a-z0-9-]+\.co$/); // tildes → punycode
});

test('normalizar: rechaza lo que no es dominio', () => {
  for (const x of ['', 'localhost', 'hola mundo', '192.168.0.1', '-malo.com', 'a..b']) {
    assert.throws(() => normalizarDominio(x), Error, x);
  }
});

test('dominio organizacional con sufijos de Colombia', () => {
  assert.equal(dominioOrganizacional('correo.unal.edu.co'), 'unal.edu.co');
  assert.equal(dominioOrganizacional('mail.google.com'), 'google.com');
  assert.equal(dominioOrganizacional('ejemplo.com.co'), 'ejemplo.com.co');
  assert.equal(dominioOrganizacional('paypal.com'), 'paypal.com');
});

test('TXT: Cloudflare (comillas y trozos de 255) y Google quedan iguales', () => {
  const cf = normalizarRespuesta(leer('cloudflare-dkim-github.json'));
  const go = real('google._domainkey.github.com|TXT');
  assert.equal(textos(cf)[0], textos(go)[0]);
  assert.ok(textos(cf)[0].length > 255);
  assert.equal(textoTXT('"v=spf1 " "-all"'), 'v=spf1 -all');
  assert.equal(textoTXT('"con \\"comillas\\""'), 'con "comillas"');
  assert.equal(textos(normalizarRespuesta(leer('cloudflare-dmarc-example.json')))[0], 'v=DMARC1;p=reject;sp=reject;adkim=s;aspf=s');
});

test('MX reales: ordenados y MX nulo de example.com', () => {
  assert.deepEqual(registrosMX(real('example.com|MX')), [{ preferencia: 0, host: '' }]);
  const mx = registrosMX(real('github.com|MX'));
  assert.ok(mx.length >= 1 && mx.every((m, i) => i === 0 || mx[i - 1].preferencia <= m.preferencia));
  assert.equal(proveedorDeMX(mx)?.nombre, 'Microsoft 365');
  assert.equal(proveedorDeMX([{ preferencia: 1, host: 'smtp.google.com' }])?.nombre, 'Google Workspace');
  assert.ok(urlDoH('google', '_dmarc.x.co', 'TXT').startsWith('https://dns.google/resolve?name=_dmarc.x.co&type=TXT'));
});

test('SPF: mecanismos, calificadores y modificadores', () => {
  const p = parsearSPF('v=spf1 ip4:192.0.2.0/24 a mx:correo.ejemplo.co include:_spf.google.com ptr ?exists:%{i}.x.co redirect=_spf.ejemplo.co -all');
  assert.equal(p.all, '-');
  assert.equal(p.redirect, '_spf.ejemplo.co');
  assert.deepEqual(p.mecanismos.map((m) => m.tipo), ['ip4', 'a', 'mx', 'include', 'ptr', 'exists', 'all']);
  assert.equal(p.mecanismos.find((m) => m.tipo === 'exists').calificador, '?');
  assert.equal(p.macros.length, 1);
  assert.equal(busquedasPropias(p), 5); // a, mx, include, ptr, exists (redirect no cuenta si hay all)
  assert.equal(busquedasPropias(parsearSPF('v=spf1 redirect=_spf.x.co')), 1);
  assert.deepEqual(buscarSPF(['google-site-verification=x', 'v=spf1 -all', 'V=SPF1 mx ~all', 'v=spf10']), ['v=spf1 -all', 'V=SPF1 mx ~all']);
});

test('SPF real de paypal.com: 7 include, sin pasarse del límite', async () => {
  const txts = textos(real('paypal.com|TXT'));
  const [spf] = buscarSPF(txts);
  assert.match(spf, /~all$/);
  const obtener = async (n) => { const r = real(`${n}|TXT`); return { estado: r.estado, txts: textos(r) }; };
  const b = await contarBusquedas('paypal.com', obtener);
  assert.ok(b.total >= 7 && b.total <= 10, `total ${b.total}`);
  assert.equal(b.nodos[0].propias, 7);
  assert.equal(b.errores.length, 0);
});

test('SPF: cuenta búsquedas anidadas, detecta el exceso, los bucles y los include vacíos', async () => {
  const zona = {
    'a.co': ['v=spf1 include:b.co include:c.co include:roto.co mx ~all'],
    'b.co': ['v=spf1 include:d.co a a:x.co -all'],
    'c.co': ['v=spf1 include:a.co ip4:192.0.2.1 -all'], // bucle de vuelta a a.co
    'd.co': ['v=spf1 mx exists:y.co ptr -all'],
  };
  const obtener = async (n) => (zona[n] ? { estado: 0, txts: zona[n] } : { estado: 3, txts: [] });
  const b = await contarBusquedas('a.co', obtener);
  // a.co: 3 include + mx = 4 · b.co: include + a + a = 3 · c.co: include = 1 · d.co: mx + exists + ptr = 3
  assert.equal(b.total, 11);
  assert.equal(b.vacias, 1);
  assert.equal(b.ptr, true);
  assert.ok(b.errores.some((e) => e.includes('bucle')));
  assert.ok(b.errores.some((e) => e.includes('roto.co')));
});

test('SPF recomendado: nulo, proveedor, fusión y final suave', () => {
  assert.equal(recomendarSPF({ registros: [], recibeCorreo: false }), 'v=spf1 -all');
  assert.equal(recomendarSPF({ registros: [], recibeCorreo: true, proveedor: { include: 'include:_spf.google.com' } }), 'v=spf1 include:_spf.google.com ~all');
  assert.equal(recomendarSPF({ registros: [], recibeCorreo: true, proveedor: null }), 'v=spf1 mx ~all');
  assert.equal(recomendarSPF({ registros: ['v=spf1 include:a.co ~all', 'v=spf1 include:b.co +a -all'], recibeCorreo: true }), 'v=spf1 include:a.co include:b.co a ~all');
  assert.equal(recomendarSPF({ registros: ['v=spf1 mx +all'], recibeCorreo: true }), 'v=spf1 mx ~all');
  assert.equal(recomendarSPF({ registros: ['v=spf1 mx -all'], recibeCorreo: true }), 'v=spf1 mx -all');
});

test('DMARC real: github (quarantine, sp=reject) y example.com (reject estricto)', () => {
  const g = parsearDMARC(buscarDMARC(textos(real('_dmarc.github.com|TXT')))[0]);
  assert.equal(g.p, 'quarantine');
  assert.equal(g.sp, 'reject');
  assert.equal(g.pct, 100);
  assert.deepEqual(g.rua, ['mailto:dmarc@github.com']);
  assert.equal(g.errores.length, 0);
  const e = parsearDMARC(textos(real('_dmarc.example.com|TXT'))[0]);
  assert.deepEqual([e.p, e.sp, e.adkim, e.aspf, e.rua.length], ['reject', 'reject', 's', 's', 0]);
});

test('DMARC: valores por defecto, errores y avisos', () => {
  const d = parsearDMARC('v=DMARC1; p=none');
  assert.deepEqual([d.p, d.sp, d.pct, d.adkim, d.aspf], ['none', 'none', 100, 'r', 'r']);
  assert.ok(parsearDMARC('p=reject; v=DMARC1').errores.length > 0); // v debe ir primero
  assert.ok(parsearDMARC('v=DMARC1; rua=mailto:a@b.co').errores.some((x) => x.includes('falta la política')));
  assert.ok(parsearDMARC('v=DMARC1; p=bloquear').errores.length > 0);
  const raro = parsearDMARC('v=DMARC1; p=reject; pct=150; adkim=x; rua=dmarc@b.co');
  assert.equal(raro.pct, 100);
  assert.equal(raro.avisos.length, 3);
  assert.deepEqual(buscarDMARC(['v=DMARC1; p=none', 'v=spf1 -all', 'v=DMARC10']), ['v=DMARC1; p=none']);
});

test('DMARC recomendado: empezar, subir, rechazar y dominio sin correo', () => {
  assert.equal(recomendarDMARC({ dmarc: null, dominio: 'x.co', recibeCorreo: true }).registro, 'v=DMARC1; p=none; rua=mailto:dmarc@x.co');
  assert.equal(recomendarDMARC({ dmarc: null, dominio: 'x.co', recibeCorreo: false }).registro, 'v=DMARC1; p=reject; sp=reject; adkim=s; aspf=s');
  const none = parsearDMARC('v=DMARC1; p=none; sp=none; rua=mailto:r@x.co');
  assert.equal(recomendarDMARC({ dmarc: none, dominio: 'x.co', recibeCorreo: true }).registro, 'v=DMARC1; p=quarantine; rua=mailto:r@x.co');
  const q = parsearDMARC('v=DMARC1; p=quarantine; pct=25; rua=mailto:r@x.co');
  assert.equal(recomendarDMARC({ dmarc: q, dominio: 'x.co', recibeCorreo: true }).registro, 'v=DMARC1; p=reject; rua=mailto:r@x.co');
  const listo = parsearDMARC('v=DMARC1; p=reject; rua=mailto:r@x.co');
  assert.deepEqual(recomendarDMARC({ dmarc: listo, dominio: 'x.co', recibeCorreo: true }), { registro: null, paso: 'listo' });
  assert.equal(construirDMARC({ rua: 'mailto:a@b.co', p: 'reject', v: 'DMARC1', zz: '1' }), 'v=DMARC1; p=reject; rua=mailto:a@b.co; zz=1');
});

test('DKIM real: claves de github, tamaño leído del DER', () => {
  const k = textos(real('google._domainkey.github.com|TXT'))[0];
  assert.ok(esDKIM(k));
  const a = analizarDKIM(k);
  assert.deepEqual([a.tipo, a.bits, a.revocada], ['rsa', 2048, false]);
  assert.equal(fuerzaDKIM(a), 'fuerte');
  // selector1 de github es un CNAME hacia Microsoft: la respuesta trae el alias y luego la clave.
  const r = real('selector1._domainkey.github.com|TXT');
  assert.ok(r.respuestas.some((x) => x.tipo === 5));
  assert.equal(analizarDKIM(textos(r).find(esDKIM)).bits, 1024);
});

test('DKIM: revocada, ed25519, modo prueba y basura', () => {
  assert.equal(fuerzaDKIM(analizarDKIM('v=DKIM1; p=')), 'revocada');
  assert.deepEqual(analizarDKIM('v=DKIM1; k=ed25519; p=11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo='), { tipo: 'ed25519', bits: 256, revocada: false, prueba: false });
  assert.equal(analizarDKIM('v=DKIM1; t=y; k=rsa; p=AAAA').prueba, true);
  assert.equal(bitsRSA('no-es-base64-valido!!'), null);
  assert.equal(esDKIM('v=spf1 -all'), false);
  assert.equal(esDKIM('v=DKIM2; p=abc'), false);
});

test('resolutor DoH: pasa a Cloudflare si Google falla y no repite preguntas', async () => {
  const llamadas = [];
  const falso = async (url) => {
    llamadas.push(url);
    if (url.startsWith('https://dns.google')) return { ok: false, status: 503 };
    return { ok: true, json: async () => leer('cloudflare-dmarc-example.json') };
  };
  const guardadas = {};
  const r = crearResolutorDoH({ fetch: falso, guardar: (k, j) => { guardadas[k] = j; } });
  const a = await r('_dmarc.example.com', 'TXT');
  await r('_DMARC.example.com.', 'txt');
  assert.equal(textos(a)[0], 'v=DMARC1;p=reject;sp=reject;adkim=s;aspf=s');
  assert.equal(llamadas.length, 2); // una a Google (falla) y una a Cloudflare; la segunda pregunta sale de la caché
  assert.deepEqual([...r.usados], ['cloudflare']);
  assert.ok('_dmarc.example.com|TXT' in guardadas);
  const caido = crearResolutorDoH({ fetch: async () => { throw new TypeError('Failed to fetch'); } });
  await assert.rejects(caido('x.co', 'TXT'), /no se pudo llegar a Google Public DNS.*no se pudo llegar a Cloudflare/);
});
