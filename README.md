# Mail DNS Check · Web service

Check a domain's SPF, DKIM, DMARC, and MX records with analysis and visual alerts, analyze a real message (`.eml`) to see whether it was actually DKIM-signed, and export everything as a PDF report.

🇮🇹 Documentazione in italiano: [README-ITALIAN.md](README-ITALIAN.md)

# Demo

https://muninn.ovh/maildns/

Direct check through a link: https://muninn.ovh/maildns/?domain=example.com

## Requirements

- Linux with PHP 7.4+ (tested on 8.x), `proc_open` enabled
- `dig` (`dnsutils` on Debian/Ubuntu, `bind-utils` on RHEL/Rocky)
- PHP `openssl` extension (optional: gives the exact RSA key size; without it the size is estimated)
- A web server with PHP support (Apache + mod_php, Nginx + PHP-FPM, or simply `php -S` for testing)

```bash
# Debian/Ubuntu
apt install php-cli php-fpm dnsutils

# RHEL/Rocky
dnf install php php-fpm bind-utils
```

## Files

```text
maildns-check/
├── index.html            # UI (Italian + English)
├── api.php               # backend (DNS queries + analysis)
├── README.md             # this file
├── README-ITALIAN.md     # Italian documentation
├── LICENSE               # GPL-3.0
├── LICENSE_PDFMAKE       # MIT (pdfmake)
└── include/
    ├── pdfmake.min.js    # PDF library (bundled, no CDN)
    └── vfs_fonts.js      # Roboto font for pdfmake
```

The files in `include/` are already included. No runtime download is needed, so it works offline and in air-gapped environments.

## Deployment

### Quick test (built-in server)

```bash
cd /path/to/maildns-check
php -S 0.0.0.0:8080
# open http://localhost:8080/
```

### Apache

Copy the entire folder into the DocumentRoot (for example, `/var/www/html/maildns/`). No extra configuration is needed.

### Nginx + PHP-FPM

```nginx
location /maildns/ {
    root /var/www/html;
    index index.html;
    try_files $uri $uri/ =404;
}
location ~ \.php$ {
    root /var/www/html;
    fastcgi_pass unix:/run/php/php-fpm.sock;
    fastcgi_index index.php;
    include fastcgi_params;
    fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
}
```

### Configuration

No configuration file is needed. The few tunables are constants at the top of `api.php`:

| Constant | Default | Meaning |
|---|---|---|
| `DEFAULT_RESOLVER` | `1.1.1.1` | Resolver used when none is given |
| `DEFAULT_LANG` | `en` | Language of API messages when none is requested or detected |
| `DIG_TIMEOUT` / `DIG_TRIES` | `2` / `2` | Seconds per try and tries of each `dig` query |
| `TIME_BUDGET` | `20` | Max seconds of DNS work per request |
| `MAX_CONCURRENT` | `4` | Max analyses running at the same time (all clients) |
| `MAX_PER_IP` | `2` | Max analyses running at the same time for one client IP |
| `RETRY_AFTER` | `5` | Seconds suggested to a client that gets HTTP 429 |
| `MAX_SELECTORS` | `100` | Max DKIM selectors per request |

To accept `.eml` files up to 5 MB, PHP needs `upload_max_filesize` and `post_max_size` of at least `5M` (the PHP default for uploads is `2M`). A larger file is rejected with a clear error.

## Features

### Language

- The interface is available in **Italian and English**.
- The language is **detected automatically** from the browser (`navigator.languages`): Italian for Italian browsers, English for everyone else.
- The `IT` / `EN` switch in the header overrides the detection; the choice is remembered in the browser (`localStorage`).
- `?lang=it` or `?lang=en` in the URL forces a language for that visit.
- The messages of the analysis are localized by the API (`lang` field, or the `Accept-Language` header), so the on-screen report, the PDF and the JSON all use the same language.

### Direct link (`?domain=`)

Open the page with a `domain` parameter and the analysis starts immediately, handy to send a live check to someone:

```text
https://your-host/maildns/?domain=example.com
https://your-host/maildns/?domain=example.com&resolver=8.8.8.8
https://your-host/maildns/?domain=example.com&selectors=selector1,google
https://your-host/maildns/?domain=example.com&lang=en
```

| Parameter | Meaning |
|---|---|
| `domain` | Domain to analyze (starts the analysis) |
| `resolver` | DNS resolver IP (optional) |
| `selectors` | Custom DKIM selectors, comma separated (optional) |
| `lang` | `it` or `en` (optional, otherwise detected) |

After every analysis the address bar is updated with the matching link, and the report shows a **Share this check** box with a copy button.

### Input
- Domain field plus DNS resolver IP
- **.eml upload** (drag and drop or click to select). The domain is detected from the `From` header, with fallback to Sender / Return-Path / Reply-To and, as a last resort, `d=` from the DKIM signature. Client-side parsing uses the first 256 KB.
- DKIM selectors are taken **only from `DKIM-Signature` headers whose `d=` is aligned with the analyzed domain** (same domain, a subdomain or a parent of it): the key lives at `<s>._domainkey.<d>`, so `s=` is always read together with its own `d=`.
- `ARC-Message-Signature` / `ARC-Seal` headers are **ignored** for DKIM lookups: they are added by intermediate servers (gateways, anti-spam filters) and their selector and domain belong to those servers, not to the sender. They are only shown as information.
- If the EML has no usable DKIM signature for the domain, the default selector list is used.
- The upload box shows the result right away: selectors found, "no signature in the message · internal mail" (blue) or "no signature in the message" (red).
- The domain taken from an EML is replaced when another EML is loaded and cleared when the EML is removed; a domain typed by hand is never overwritten.
- Advanced options: custom DKIM selectors. They are **checked together with** the selectors found in the EML.

### Message analysis (EML)
Shown as a highlighted card at the top of the report (and as the first section of the PDF) whenever an `.eml` is uploaded. It distinguishes the **signature in the message** from the **keys published in DNS**:

| Result | Color | Meaning |
|---|---|---|
| DKIM-signed message | green | Signature aligned with the domain, active key found in DNS |
| No signature · internal mail | blue | Sender and all To/Cc recipients in the same domain: Microsoft 365 and other providers do not DKIM-sign mail that stays inside the tenant |
| No signature in the message | red | Sent to external recipients without `DKIM-Signature`; the card says whether keys exist in DNS (sending problem) or not (DKIM not configured) |
| DKIM signature not aligned | red | Signed only by other domains (e.g. an ESP's own domain): does not count for DMARC alignment |
| Signed with a revoked key | red | The selector used by the signature has an empty `p=` in DNS: verification fails at the recipient |
| Signature present, key not found | yellow | The selector used in the signature has no key in DNS: verification will fail at the recipient |

**Alignment** follows the DMARC `adkim` tag of the domain:

- `exact`: `d=` is identical to the sender domain. Always aligned.
- `relaxed`: `d=` is a subdomain or a parent of the sender domain (e.g. `d=mail.example.com` for `example.com`). Aligned with the default `adkim=r`, **not** aligned with `adkim=s`.
- Limitation: the Public Suffix List is not used, so two sibling subdomains (`a.example.com` / `b.example.com`) are reported as not aligned although relaxed alignment would accept them.

The card also lists sender/recipient domains, internal/external, DKIM signatures found with their alignment, other non-aligned signatures and ignored ARC signatures.

### MX
- Sorted list by priority
- Alert if no MX records are found or if only one MX record is present

### SPF
- Parses mechanisms and the final `all` qualifier
- **Follows the `redirect=` modifier** up to 5 levels, with loop detection
- Distinguishes mechanisms from the **local record** vs the **effective record** after redirect
- **Counts DNS lookups over the whole evaluation tree** (RFC 7208 limit: 10): `include`, `a`, `mx`, `ptr`, `exists` and `redirect`, including the terms of every nested `include:` and the `a/24` / `mx/24` forms. The resolved includes are listed.
- Alerts for: `+all`, `?all`, lookups > 10, lookups >= 8, multiple records, redirect or include to a domain without SPF, loops
- Recognizes that `all` is not needed in the local record when `redirect=` is present

### DMARC
- **Management mode**: `CNAME` (delegated), `direct TXT`, or **conflict** (both present)
- If CNAME is used, resolves the target and analyzes its TXT record
- **Prominent animated pulse alert** when a CNAME + TXT conflict is detected (RFC 1034 violation)
- Tag parsing: `p`, `sp`, `pct`, `rua`, `ruf`, `adkim`, `aspf`, `fo`
- `rua` and `ruf` are shown in dedicated boxes that support multiple values

### DKIM
- Default list of about 75 selectors (M365, Google, OVHcloud MX Plan, Fastmail, Hostinger, common ESPs such as Brevo, Mailjet, MailerLite, Constant Contact and Klaviyo, date-based selectors)
- Selectors that embed a per-account ID (e.g. OVHcloud Exchange / Email Pro `ovhexNNNNNN-selector1`, HubSpot `hs1-<id>`) cannot be guessed: upload an `.eml` or enter them as custom selectors
- Selectors extracted from the uploaded EML file (aligned `DKIM-Signature` only, see above), merged with the custom ones
- CNAME-delegated selectors (e.g. Microsoft 365 `selectorN-<tenant>._domainkey.<tenant>.<x>.dkim.mail.microsoft`) are followed correctly with a **single query per selector**: only real TXT records are shown, the CNAME target is never mistaken for a TXT value
- Note when a CNAME exists but no key is published at the target (normal for the inactive Microsoft 365 selector until the next key rotation)
- **Key state** for each selector, shown as a badge:

  | State | Meaning |
  |---|---|
  | Active | A public key is published |
  | Testing | Key published with the `t=y` flag |
  | Revoked | `p=` is empty: per RFC 6376 §3.6.1 the key has been revoked |
  | No key | CNAME present, no key at the target |

- A revoked key is **informational** when it is just an old selector left in DNS after a rotation, and **critical** when the uploaded message is signed with that very selector. The section turns to warning when selectors exist but none has an active key.
- **Real key size**: the RSA modulus is read with OpenSSL (1024 vs 2048 bit and so on); Ed25519 keys (`k=ed25519`) are recognized and not flagged as short.
- **Wildcard protection**: a random selector is queried first. If the zone answers for it (wildcard TXT/CNAME), identical answers are discarded, and a TXT that is not a DKIM record (no `p=`, or `v=` different from `DKIM1`) is never listed as a selector.

### PDF report
The "Download PDF" button appears at the bottom of the report. The PDF is generated client-side with **pdfmake** directly from the API JSON, in the current language: no rasterization, clean vector layout, and native text wrapping. Automatic filename: `maildns-<domain>-<timestamp>.pdf`.

The page footer shows the address of **the instance that generated the report** (taken from the page URL, nothing is hardcoded), linking to the same check.

**Page-break-aware layout**:
- Every logical block (TXT record, alert, key/value table, tag row, whole DKIM selector, EML analysis box) is kept on a single page: if it does not fit in the remaining space it moves to the next page as a whole.
- Section titles and inner labels always stay together with the block that follows, so they are never left alone at the bottom of a page.
- pdfmake silently **drops** an unbreakable block taller than a page. To prevent this, block height is estimated conservatively and blocks above ~70% of the usable page height stay breakable (e.g. very long MX tables or SPF records); content is never lost.

### Interface
- **Language switch** (IT / EN) and **theme selector** (Auto / Light / Dark) in the header. Auto follows the operating system / browser preference (`prefers-color-scheme`). Both choices are remembered in the browser (`localStorage`); the theme is applied before the page renders, so there is no flash of the wrong theme.
- When the server is busy the page queues the request and retries by itself, showing a countdown.
- Readable error when the server answer is not JSON (e.g. a proxy error page).
- Footer with copyright and license.

## Security

- Inputs validated with regex (domain, selector, resolver IP). Selectors must start with a letter or a digit, so a name handed to `dig` can never be read as a command-line option.
- `dig` invoked through `proc_open` with arguments passed as an **array**. No shell injection
- **DNS errors are never mistaken for "record not found"**: timeouts, `SERVFAIL`/`REFUSED` and a missing `dig` are reported as such (section status `N/A`), and an unreachable resolver stops the request immediately with HTTP 502.
- **Abuse limits, without touching the web server**:
  - at most `MAX_CONCURRENT` analyses at the same time overall and `MAX_PER_IP` per client IP (file locks), so a single client cannot take every slot; extra requests get HTTP 429 with `Retry-After`
  - **client-side queue**: on HTTP 429 the web page shows "you are in the queue", waits the `Retry-After` time and retries by itself for up to 60 seconds. No PHP worker is held while waiting. The queue is not ordered: whoever retries first after a slot frees up gets it
  - the per-IP limit uses `REMOTE_ADDR` only (`X-Forwarded-For` can be forged) and groups IPv6 clients by /64. Behind a reverse proxy on another host every visitor shares the proxy address: raise `MAX_PER_IP` to the value of `MAX_CONCURRENT` in that case
  - at most `TIME_BUDGET` seconds of DNS work per request; selectors left unchecked are reported
  - the resolver is probed with one query before the analysis starts
  - limit of 100 selectors per request, one DNS query per selector
  - the SPF include tree is walked with a cap on depth and queries
- Limit of 5 MB for `.eml` files (multipart and JSON); upload errors and oversized requests return a clear error instead of being ignored
- JSON input is type-checked
- EML parsing is limited to the header block; values extracted from the message are validated before use and escaped before display
- `X-Content-Type-Options: nosniff`, `Cache-Control: no-store`

Still up to you: the resolver field accepts any IP address, including private ones (useful on internal networks). On a public instance consider a rate limit at the web server or firewall level.

## API

`POST /api.php`

### Multipart form

```text
domain=example.com
resolver=1.1.1.1                # optional
selectors=selector1, google     # optional
lang=en                         # optional: it | en
eml=@/path/to/mail.eml          # optional
```

### JSON

```json
{
  "domain": "example.com",
  "resolver": "1.1.1.1",
  "selectors": ["selector1", "google"],
  "lang": "en",
  "eml_b64": "..."
}
```

Selectors: custom selectors and aligned selectors from the EML are merged; the default list is used only when neither is given.

Language: `lang` field > `Accept-Language` header > `DEFAULT_LANG`.

### Response (main fields)

```json
{
  "domain": "example.com",
  "resolver": "1.1.1.1",
  "lang": "en",
  "timestamp": "2026-10-19T07:00:00+00:00",
  "eml_selectors_extracted": ["selector1"],
  "selectors_used": ["selector1"],
  "eml": {
    "dkim_signed": true,
    "internal": false,
    "from_domains": ["example.com"],
    "rcpt_domains": ["gmail.com"],
    "dkim_signatures": [{ "s": "selector1", "d": "example.com", "alignment": "exact" }],
    "arc_signatures": [{ "s": "arc-20181011", "d": "gateway.example" }]
  },
  "mx": { "...": "..." },
  "spf": { "lookups": 4, "includes": ["spf.protection.outlook.com"], "...": "..." },
  "dmarc": { "...": "..." },
  "dkim": {
    "tried": 1, "count": 1, "active_count": 1, "revoked_count": 0,
    "errors": 0, "truncated": false, "issues": [],
    "found": [{
      "selector": "selector1", "domain": "example.com",
      "state": "active", "key_type": "rsa", "key_bits": 2048,
      "cname": [], "txt": ["v=DKIM1; k=rsa; p=..."], "tags": { "...": "..." }, "issues": []
    }]
  },
  "dns_errors": 0,
  "overall_status": "ok",
  "elapsed_ms": 120
}
```

- `eml` is `null` when no EML is uploaded. `alignment` is `exact`, `relaxed` or `none`.
- `dkim.found[].state` is `active`, `testing`, `revoked` or `no_key`.
- Section `status` and `overall_status` are `ok`, `warning`, `critical` or `unknown` (DNS errors).

### Errors

Errors are returned as `{"error": "..."}` in the request language.

| HTTP | Cause |
|---|---|
| 400 | Invalid domain, resolver, JSON or upload |
| 405 | Method other than POST |
| 413 | EML or request too large |
| 429 | Too many analyses in progress, overall (`"scope": "global"`) or from the same IP (`"scope": "ip"`). The body carries `retry_after` (seconds), also sent as the `Retry-After` header: wait and retry |
| 500 | `dig` missing or `proc_open` disabled |
| 502 | Resolver not answering, or answering `SERVFAIL`/`REFUSED` |

### CLI (curl)

```bash
curl -X POST http://localhost:8080/api.php -F domain=example.com -F selectors="selector1 selector2"

# With EML file, messages in Italian
curl -X POST http://localhost:8080/api.php -F domain=example.com -F lang=it -F eml=@mail.eml
```

> Tip: to check whether outgoing mail is really DKIM-signed, upload a message sent to an **external** recipient. Mail between mailboxes of the same domain is usually not signed by Microsoft 365.

## Credits and licenses

This project includes third-party software:

- **[pdfmake](https://github.com/bpampuch/pdfmake)** v0.2.10 by Bartek Pampuch and contributors, distributed under the **MIT** license. Client-side PDF report generation.
  - Files: `include/pdfmake.min.js`, `include/vfs_fonts.js`
  - Website: [http://pdfmake.org](http://pdfmake.org)
- **Roboto** font (included in pdfmake's vfs), Google Fonts, licensed under Apache 2.0.

The rest of the code is original.

## License

This project is released under the **GNU General Public License v3.0** (GPL-3.0). See [LICENSE](LICENSE) or <https://www.gnu.org/licenses/gpl-3.0.html>.

Third-party components keep their own licenses (see above).

## Author

https://github.com/Leproide
