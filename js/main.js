// Página principal: lee el dominio, consulta el DNS (o el respaldo), puntúa y pinta el veredicto y las tarjetas.
import { iniciarTema } from './tema.js';
import { normalizarDominio } from './dominio.js';
import { crearResolutorDoH, crearResolutorGuardado, PROVEEDORES } from './dns.js';
import { analizar } from './analizar.js';
import { puntuar } from './puntuar.js';

const $ = (id) => document.getElementById(id);
const RESPALDO = { ruta: 'datos/ejemplo-2026-11-10.json', fecha: '10 nov 2026' };
const EJEMPLO_INICIAL = 'paypal.com';
const NOMBRE_TIPO = { mx: 'MX', spf: 'TXT', dmarc: 'TXT', dkim: 'TXT', mtasts: 'TXT', tlsrpt: 'TXT', bimi: 'TXT' };
const ETIQUETA_EST = { bien: 'Bien', regular: 'Mejorable', mal: 'Mal', info: 'Info' };

const params = new URLSearchParams(location.search);
const sinConexion = params.has('sin-conexion');

function el(tag, attrs = {}, ...hijos) {
  const n = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (v == null) continue;
    if (k === 'class') n.className = v; else if (k === 'text') n.textContent = v; else n.setAttribute(k, v);
  }
  for (const h of hijos) if (h != null && h !== false) n.append(h);
  return n;
}

let respaldoP = null;
function respaldo() {
  respaldoP ??= fetch(RESPALDO.ruta).then((r) => {
    if (!r.ok) throw new Error(`el archivo de ejemplo respondió ${r.status}`);
    return r.json();
  }).catch((e) => { respaldoP = null; throw e; });
  return respaldoP;
}

// ---------------------------------------------------------------- estados de la respuesta
function pintarCarga(dominio) {
  const caja = $('respuesta');
  caja.dataset.tono = 'carga';
  caja.setAttribute('aria-busy', 'true');
  $('onoma').textContent = 'PING…';
  $('nota').textContent = '…';
  $('pregunta').textContent = `Revisando ${dominio}`;
  $('veredicto').replaceChildren(el('span', { class: 'cargando-txt', text: 'Consultando el DNS…' }));
  $('sub-veredicto').textContent = 'MX, SPF, DMARC, 20 selectores DKIM y extras, en paralelo.';
  $('barra').firstElementChild.style.width = '0';
  $('puntos').textContent = '– / 100';
  $('estado').replaceChildren(el('span', { class: 'chip chip-carga', text: 'Cargando' }));
  $('tarjetas').replaceChildren(...['DMARC', 'SPF', 'DKIM', 'MX'].map((t) => el('article', { class: 'tarjeta vineta esqueleto', 'aria-hidden': 'true' },
    el('div', { class: 'tarjeta-cab' }, el('h3', { text: t })))));
}

function pintarError(titulo, detalle, dominio) {
  const caja = $('respuesta');
  caja.dataset.tono = 'error';
  caja.setAttribute('aria-busy', 'false');
  $('onoma').textContent = '¿?';
  $('nota').textContent = '?';
  $('pregunta').textContent = dominio ? `No se pudo revisar ${dominio}` : 'No se pudo revisar';
  $('veredicto').textContent = titulo;
  $('sub-veredicto').textContent = detalle;
  $('barra').firstElementChild.style.width = '0';
  $('puntos').textContent = '– / 100';
  $('estado').replaceChildren(el('span', { class: 'chip chip-error', text: 'Error' }),
    el('span', { class: 'motivo', text: 'Prueba con uno de los ejemplos: funcionan aunque no haya conexión.' }));
  $('tarjetas').replaceChildren();
}

function chipOrigen(origen, resolver, motivo) {
  const nodos = [];
  if (origen === 'vivo') {
    const usados = [...resolver.usados].map((p) => PROVEEDORES[p]?.nombre ?? p).join(' + ');
    nodos.push(el('span', { class: 'chip chip-vivo', text: 'En vivo' }), el('span', { text: `vía ${usados || 'DoH'} · ${new Date().toLocaleTimeString('es-CO', { hour: 'numeric', minute: '2-digit' })}` }));
  } else {
    nodos.push(el('span', { class: 'chip chip-ejemplo', text: `Sin conexión: datos de ejemplo del ${RESPALDO.fecha}` }));
  }
  if (motivo) nodos.push(el('span', { class: 'motivo', text: `Qué pasó: ${motivo}` }));
  return nodos;
}

// ---------------------------------------------------------------- tarjetas
async function copiar(texto, boton) {
  let ok = false;
  try { await navigator.clipboard.writeText(texto); ok = true; } catch { /* sin portapapeles: se selecciona */ }
  if (!ok) {
    const pre = boton.previousElementSibling;
    const rango = document.createRange();
    rango.selectNodeContents(pre);
    const sel = getSelection();
    sel.removeAllRanges();
    sel.addRange(rango);
  }
  const antes = boton.textContent;
  boton.textContent = ok ? 'Copiado' : 'Seleccionado: Ctrl+C';
  setTimeout(() => { boton.textContent = antes; }, 1800);
}

function bloqueRegistro(clase, titulo, nombre, tipo, valor, conCopiar) {
  const pre = el('pre', { text: valor });
  const caja = el('div', { class: `reg ${clase}` },
    el('p', { class: 'reg-t' }, el('span', { text: titulo }), nombre ? el('code', { text: `${tipo} ${nombre}` }) : null), pre);
  if (conCopiar) {
    const b = el('button', { type: 'button', class: 'mini copiar', text: 'Copiar registro', 'aria-label': `Copiar el registro recomendado de ${titulo}` });
    b.addEventListener('click', () => copiar(valor, b));
    caja.append(b);
  }
  return caja;
}

function tarjeta(t) {
  const recEsRegistro = Boolean(t.recomendado) && !/^Genera/.test(t.recomendado);
  const cuerpo = el('div', { class: 'tarjeta-cuerpo' },
    el('p', { text: t.explica }),
    t.detalle.length ? el('ul', {}, ...t.detalle.map((d) => el('li', { text: d }))) : null,
    t.actual ? bloqueRegistro('actual', 'Tu registro', t.nombre, NOMBRE_TIPO[t.id] ?? 'TXT', t.actual, false) : null,
    recEsRegistro ? bloqueRegistro('recomendado', t.id === 'dkim' ? 'Plantilla' : t.paso === 'subir' ? 'Siguiente paso' : 'Recomendado', t.nombre, 'TXT', t.recomendado, true) : null,
    t.recomendado && !recEsRegistro ? el('p', { class: 'pasos', text: t.recomendado }) : null,
    t.id === 'dmarc' && t.paso === 'empezar' ? el('p', { class: 'pasos', text: 'Empieza con p=none y revisa los informes 2 a 4 semanas; luego sube a p=quarantine y después a p=reject.' }) : null,
  );
  return el('article', { class: `tarjeta vineta est-${t.estado}`, id: `t-${t.id}` },
    el('div', { class: 'tarjeta-cab' },
      el('h3', { text: t.titulo }),
      t.max ? el('span', { class: 'tarjeta-pts', text: `${t.puntos}/${t.max}` }) : null,
      el('span', { class: `chip c-${t.estado}`, text: t.etiqueta, title: ETIQUETA_EST[t.estado] })),
    cuerpo);
}

function pintarResultado(dominio, r, { origen, resolver, motivo, quitoWww, esEjemplo }) {
  const caja = $('respuesta');
  caja.dataset.tono = r.tono;
  caja.setAttribute('aria-busy', 'false');
  $('onoma').textContent = r.onoma;
  $('nota').textContent = r.nota;
  $('pregunta').textContent = `${esEjemplo ? 'Ejemplo · ' : ''}${dominio}${quitoWww ? ' (sin el www.)' : ''} · nota ${r.nota}`;
  $('veredicto').textContent = r.titulo;
  $('sub-veredicto').textContent = r.sub + (r.tope ? ' · Sin DMARC que bloquee, la nota no pasa de D.' : '');
  $('barra').firstElementChild.style.width = `${r.puntos}%`;
  $('barra').setAttribute('aria-valuenow', String(r.puntos));
  $('puntos').textContent = `${String(r.puntos).replace('.', ',')} / 100`;
  $('estado').replaceChildren(...chipOrigen(origen, resolver, motivo));
  $('tarjetas').replaceChildren(...r.tarjetas.map(tarjeta));
}

// ---------------------------------------------------------------- flujo
let ronda = 0;

async function revisar(entrada, { esEjemplo = false } = {}) {
  const ayuda = $('ayuda-dominio');
  const input = $('dominio');
  let dominio;
  let quitoWww;
  try {
    ({ dominio, quitoWww } = normalizarDominio(entrada));
  } catch (e) {
    ayuda.textContent = e.message;
    ayuda.classList.add('error');
    input.setAttribute('aria-invalid', 'true');
    input.focus();
    return;
  }
  ayuda.textContent = 'Sirve un dominio, una URL o un correo: se queda con lo que va después de la @.';
  ayuda.classList.remove('error');
  input.removeAttribute('aria-invalid');
  for (const b of document.querySelectorAll('[data-ejemplo]')) b.setAttribute('aria-pressed', String(b.dataset.ejemplo === dominio));

  const r = ++ronda;
  const boton = $('revisar');
  boton.disabled = true;
  pintarCarga(dominio);
  if (!esEjemplo) {
    const url = new URL(location.href);
    url.searchParams.set('dominio', dominio);
    history.replaceState(null, '', url);
  }

  let hechos;
  let origen = 'vivo';
  let resolver;
  let motivo = null;
  try {
    if (sinConexion) throw Object.assign(new Error('modo sin conexión forzado con ?sin-conexion'), { forzado: true });
    resolver = crearResolutorDoH();
    hechos = await analizar(dominio, resolver);
    if (resolver.errores.length) motivo = `algunas consultas fallaron (${resolver.errores.length}); los controles afectados salen como «Sin respuesta» o «No encontrado».`;
  } catch (e) {
    motivo = e.message;
    try {
      const datos = await respaldo();
      if (!datos.dominios.includes(dominio)) {
        if (r !== ronda) return;
        pintarError(e.forzado ? 'Sin conexión' : 'No hay respuesta del DNS',
          `${e.forzado ? 'Estás en el modo sin conexión' : `No se pudo consultar: ${e.message}`}. Sin conexión solo están guardados ${datos.dominios.join(', ')}.`, dominio);
        boton.disabled = false;
        return;
      }
      resolver = crearResolutorGuardado(datos.respuestas);
      hechos = await analizar(dominio, resolver);
      origen = 'respaldo';
    } catch (e2) {
      if (r !== ronda) return;
      pintarError('No hay respuesta del DNS', `${e.message}. Tampoco se pudo leer el archivo de ejemplo (${e2.message}).`, dominio);
      boton.disabled = false;
      return;
    }
  }
  if (r !== ronda) return;
  boton.disabled = false;
  if (!hechos.existe) {
    pintarError('Ese dominio no existe', `El DNS responde que ${dominio} no está registrado (NXDOMAIN). Revisa cómo lo escribiste.`, dominio);
    return;
  }
  pintarResultado(dominio, puntuar(hechos), { origen, resolver, motivo: origen === 'respaldo' || motivo ? motivo : null, quitoWww, esEjemplo });
}

iniciarTema($('tema'));
$('form').addEventListener('submit', (ev) => {
  ev.preventDefault();
  revisar($('dominio').value);
});
for (const b of document.querySelectorAll('[data-ejemplo]')) {
  b.addEventListener('click', () => {
    $('dominio').value = b.dataset.ejemplo;
    revisar(b.dataset.ejemplo, { esEjemplo: true });
  });
}
const pedido = params.get('dominio');
if (pedido) {
  $('dominio').value = pedido;
  revisar(pedido, { esEjemplo: false });
} else {
  revisar(EJEMPLO_INICIAL, { esEjemplo: true });
}
