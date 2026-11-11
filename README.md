# ¿Tu dominio se puede suplantar?

**Español** · [English](README.en.md)

Una página que hace una sola cosa: escribes un dominio (por ejemplo `ecci.edu.co`) y te dice, con un **veredicto** y una **nota de la A a la F**, qué tan fácil es enviar correos falsos haciéndose pasar por él, y qué registro DNS publicar para arreglarlo.

- Consulta el DNS desde tu navegador con **DNS sobre HTTPS** ([Google Public DNS](https://developers.google.com/speed/public-dns/docs/doh/json) y, si falla, [Cloudflare](https://developers.cloudflare.com/1.1.1.1/encryption/dns-over-https/make-api-requests/dns-json/)); las dos responden con CORS abierto y sin clave.
- **MX:** ¿recibe correo? (incluye el MX nulo de la RFC 7505).
- **SPF** (RFC 7208): si existe, si hay más de uno, el final (`-all`, `~all`, `?all`, `+all`), las búsquedas DNS siguiendo los `include` (límite 10, y 2 vacías), macros y el mecanismo obsoleto `ptr`.
- **DMARC** (RFC 7489): `p`, `sp`, `pct`, `rua`, alineación; si un subdominio no tiene registro, hereda el del dominio organizacional.
- **DKIM** (RFC 6376): prueba 20 selectores comunes y lee el tamaño real de la clave RSA. No se puede listar desde fuera, y la página lo explica.
- **Extras:** DNSSEC (bandera AD), MTA-STS, TLS-RPT y BIMI.
- Una tarjeta por control con el estado, qué significa en lenguaje claro y el **registro recomendado listo para copiar** (en DMARC, el siguiente paso: none → quarantine → reject).
- Abre con un ejemplo real (paypal.com). Estado de carga, de error (dominio inexistente, red caída) y modo **sin conexión** con respuestas reales guardadas el 10 nov 2026 (`?sin-conexion`). `?dominio=x.co` abre un dominio directamente.
- `/proceso/`: cómo funciona la suplantación, qué protege cada registro, cómo se puntúa, una muestra de 30 dominios colombianos, el marco legal (Ley 1273, arts. 269G y 269F), limitaciones y fuentes.

> **Uso ético.** Solo lee registros DNS públicos, lo mismo que hace cualquier servidor de correo. No envía correos ni entra a ningún sistema. No es asesoría jurídica ni reemplaza una auditoría.

## Muestra (calculado aquí, 10 nov 2026)

Con la misma lógica, 15 dominios `.gov.co` y 15 `.edu.co` conocidos (no al azar):

| | p=reject | p=quarantine | p=none | sin DMARC | «Fácil de suplantar» |
|---|---|---|---|---|---|
| .gov.co (15) | 4 | 9 | 1 | 1 | 2 |
| .edu.co (15) | 3 | 5 | 7 | 0 | 7 |
| Total (30) | **7** | 14 | 8 | 1 | **9** |

28 de 30 tienen SPF y 28 una clave DKIM visible; 2 firman su zona con DNSSEC y ninguno tiene MTA-STS. Solo se publican totales (`datos/estudio-2026-11-10.json`); se repite con `node scripts/estudio.mjs`.

## Uso

```bash
python3 -m http.server 8000   # y abrir http://localhost:8000
node --test                   # 29 pruebas (Node 20 o superior)
node scripts/capturar.mjs datos/ejemplo-AAAA-MM-DD.json paypal.com github.com   # regrabar respuestas
```

Para GitHub Pages basta con servir la rama `main` desde la raíz.

## Estructura

```
index.html, proceso/index.html   las dos páginas (sin build)
css/estilo.css                   línea "Tinta y trama" (claro) y "Jisseki" (oscuro)
js/dominio.js                    normalizar la entrada y dominio organizacional
js/dns.js                        DoH (Google → Cloudflare), normalizar TXT, resolutor guardado
js/spf.js, js/dmarc.js, js/dkim.js   leer cada registro y proponer el arreglo
js/analizar.js                   reúne los hechos DNS de un dominio
js/puntuar.js                    puntos, nota A–F, veredicto y tarjetas
js/graficas.js                   SVG de /proceso/
js/main.js, js/proceso.js, js/tema.js   interfaz
datos/                           respaldo sin conexión y totales de la muestra
scripts/                         grabar respuestas y repetir la muestra
test/                            pruebas node --test con respuestas DNS reales
```

## De qué trabajo sale

De la exposición «Prevención frente a los Delitos Informáticos. Responsabilidad legal en TIC» de Mario y David (con su equipo), que trató el phishing y la suplantación de sitios web como delitos (Ley 1273 de 2009, art. 269G) y la prevención con buenas prácticas técnicas. Aquí la prevención se vuelve una revisión concreta: los tres registros DNS que impiden que alguien mande correos a tu nombre.

## Créditos y licencias

- Normas: RFC 7208, 7489, 6376, 8301, 7505, 8461 y 8460; guía de M3AAWG y directiva BOD 18-01 de CISA.
- Fuentes tipográficas: Bangers, Atkinson Hyperlegible e IBM Plex Mono (Google Fonts, licencia OFL).
- [Mario Puerta «ale0009»](https://github.com/ale0009) × [David Rincón «Kuronoma»](https://www.linkedin.com/in/davidalexanderrinconcorredorkuronoma/)

Código con licencia MIT © 2026 Mario Alejandro Puerta Alarcón y David Alexander Rincón Corredor.
