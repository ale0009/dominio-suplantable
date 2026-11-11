# Can your domain be spoofed?

[Español](README.md) · **English**

A single-purpose page: type a domain and get a **verdict** and an **A–F grade** for how easy it is to send fake email pretending to be it, plus the exact DNS record to publish to fix it.

- Queries DNS from your browser with **DNS over HTTPS** (Google Public DNS, falling back to Cloudflare); both allow CORS and need no key.
- **MX**, **SPF** (RFC 7208: duplicates, `all` qualifier, 10-lookup limit following `include`, void lookups, macros, `ptr`), **DMARC** (RFC 7489: `p`, `sp`, `pct`, `rua`, alignment, organizational-domain fallback), **DKIM** (RFC 6376: 20 common selectors, real RSA key size; selectors cannot be enumerated) and extras: DNSSEC (AD flag), MTA-STS, TLS-RPT, BIMI.
- One card per control with a plain-language explanation and a **copy-ready recommended record** (DMARC moves one step at a time: none → quarantine → reject).
- Opens with a real example (paypal.com). Loading and error states, and an **offline mode** with real responses saved on 10 Nov 2026 (`?sin-conexion`). `?dominio=x.co` opens a domain directly.
- `/proceso/` (Spanish): how spoofing works, what each record protects, the scoring, a sample of 30 Colombian `.gov.co`/`.edu.co` domains (7 of 30 with `p=reject`, 9 of 30 "easy to spoof"), Colombian law (Law 1273, arts. 269G and 269F), limitations and sources.

> **Ethical use.** It only reads public DNS records, as any mail server does. It sends no email and accesses no system. Not legal advice.

## Usage

```bash
python3 -m http.server 8000   # open http://localhost:8000
node --test                   # 29 tests (Node 20+)
```

## Origin

Built from Mario and David's university presentation on preventing computer crime and legal responsibility in ICT (Colombian Law 1273 of 2009, art. 269G on website spoofing).

## Credits and licenses

- Standards: RFC 7208, 7489, 6376, 8301, 7505, 8461, 8460; M3AAWG best practices; CISA BOD 18-01.
- Fonts: Bangers, Atkinson Hyperlegible, IBM Plex Mono (Google Fonts, OFL).
- [Mario Puerta «ale0009»](https://github.com/ale0009) × [David Rincón «Kuronoma»](https://www.linkedin.com/in/davidalexanderrinconcorredorkuronoma/)

MIT License © 2026 Mario Alejandro Puerta Alarcón and David Alexander Rincón Corredor.
