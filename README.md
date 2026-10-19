# Mail DNS Check · Web service

Check a domain's SPF, DKIM, DMARC, and MX records with analysis and visual alerts, analyze a real message (`.eml`) to see whether it was actually DKIM-signed, and export everything as a PDF report.

# Demo

https://muninn.ovh/maildns/

## Note

The project is intended for personal use and is currently localized in Italian.

English translation and automatic language detection for localization will be implemented in the future.


## Requirements

- Linux with PHP 7.4+ (tested on 8.x)
- `dig` (`dnsutils` on Debian/Ubuntu, `bind-utils` on RHEL/Rocky)
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
├── index.html            # UI
├── api.php               # backend (DNS queries + analysis)
├── README.md
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

## Features

### Input
- Domain field plus DNS resolver IP
- **.eml upload** (drag and drop or click to select). The domain is detected from the `From` header, with fallback to Sender / Return-Path / Reply-To and, as a last resort, `d=` from the DKIM signature. Client-side parsing uses the first 256 KB.
- DKIM selectors are taken **only from `DKIM-Signature` headers whose `d=` matches the analyzed domain**: the key lives at `<s>._domainkey.<d>`, so `s=` is always read together with its own `d=`.
- `ARC-Message-Signature` / `ARC-Seal` headers are **ignored** for DKIM lookups: they are added by intermediate servers (gateways, anti-spam filters) and their selector and domain belong to those servers, not to the sender. They are only shown as information.
- If the EML has no usable DKIM signature for the domain, the default selector list is used.
- The upload box shows the result right away: selectors found, "no signature in the message · internal mail" (blue) or "no signature in the message" (red).
- Advanced options: custom DKIM selectors

### Message analysis (EML)
Shown as a highlighted card at the top of the report (and as the first section of the PDF) whenever an `.eml` is uploaded. It distinguishes the **signature in the message** from the **keys published in DNS**:

| Result | Color | Meaning |
|---|---|---|
| DKIM-signed message | green | Signature with `d=` of the domain, matching key found in DNS |
| No signature · internal mail | blue | Sender and all To/Cc recipients in the same domain: Microsoft 365 and other providers do not DKIM-sign mail that stays inside the tenant |
| No signature in the message | red | Sent to external recipients without `DKIM-Signature`; the card says whether keys exist in DNS (sending problem) or not (DKIM not configured) |
| DKIM signature not aligned | red | Signed only by other domains (e.g. an ESP's own domain): does not count for DMARC alignment |
| Signature present, key not found | yellow | The selector used in the signature has no key in DNS: verification will fail at the recipient |

The card also lists sender/recipient domains, internal/external, DKIM signatures found, other non-aligned signatures and ignored ARC signatures.

### MX
- Sorted list by priority
- Alert if no MX records are found or if only one MX record is present

### SPF
- Parses mechanisms and the final `all` qualifier
- **Follows the `redirect=` modifier** up to 5 levels, with loop detection
- Distinguishes mechanisms from the **local record** vs the **effective record** after redirect
- Counts total DNS lookups across the full chain (RFC 7208 limit: 10)
- Alerts for: `+all`, `?all`, lookups > 10, lookups >= 8, multiple records, redirect to a domain without SPF, loops
- Recognizes that `all` is not needed in the local record when `redirect=` is present

### DMARC
- **Management mode**: `CNAME` (delegated), `direct TXT`, or **conflict** (both present)
- If CNAME is used, resolves the target and analyzes its TXT record
- **Prominent animated pulse alert** when a CNAME + TXT conflict is detected (RFC 1034 violation)
- Tag parsing: `p`, `sp`, `pct`, `rua`, `ruf`, `adkim`, `aspf`, `fo`
- `rua` and `ruf` are shown in dedicated boxes that support multiple values

### DKIM
- Default list of about 60 selectors (M365, Google, common ESPs, date-based selectors)
- Selectors extracted from the uploaded EML file (aligned `DKIM-Signature` only, see above)
- Custom selectors via text field
- CNAME-delegated selectors (e.g. Microsoft 365 `selectorN-<tenant>._domainkey.<tenant>.<x>.dkim.mail.microsoft`) are followed correctly: only real TXT records are shown, the CNAME target is never mistaken for a TXT value
- Note when a CNAME exists but no key is published at the target (normal for the inactive Microsoft 365 selector until the next key rotation)
- For each selector: tag parsing, key size estimation (1024 vs 2048 bit), testing flag (`t=y`), revocations (`p=` empty)

### PDF report
The "Download PDF" button appears at the bottom of the report. The PDF is generated client-side with **pdfmake** directly from the API JSON: no rasterization, clean vector layout, and native text wrapping. Automatic filename: `maildns-<domain>-<timestamp>.pdf`.

**Page-break-aware layout**:
- Every logical block (TXT record, alert, key/value table, tag row, whole DKIM selector, EML analysis box) is kept on a single page: if it does not fit in the remaining space it moves to the next page as a whole.
- Section titles and inner labels ("Tag parsing", "Catena redirect", …) always stay together with the block that follows, so they are never left alone at the bottom of a page.
- pdfmake silently **drops** an unbreakable block taller than a page. To prevent this, block height is estimated conservatively and blocks above ~70% of the usable page height stay breakable (e.g. very long MX tables or SPF records); content is never lost.

Verified with a fuzz test on 600+ random reports (0–120 MX, SPF records up to 400 mechanisms, redirect chains, up to 15 DKIM selectors with very long keys, alerts up to 600 words, with and without EML): no unbreakable block split across pages and no content lost.

### Interface
- **Theme selector** (Auto / Light / Dark) in the header. Auto follows the operating system / browser preference (`prefers-color-scheme`). The choice is remembered in the browser (`localStorage`) and applied before the page renders, so there is no flash of the wrong theme.
- Footer with copyright and license.

## Security

- Inputs validated with regex (domain, selector, resolver IP)
- `dig` invoked through `proc_open` with arguments passed as an **array**. No shell injection
- Limit of 100 selectors per request
- Limit of 5 MB for `.eml` files
- EML parsing is limited to the header block; values extracted from the message are validated before use and escaped before display
- `X-Content-Type-Options: nosniff`

## API

`POST /api.php`

### Multipart form

```text
domain=example.com
resolver=1.1.1.1                # optional
selectors=selector1, google     # optional
eml=@/path/to/mail.eml          # optional
```

### JSON

```json
{
  "domain": "example.com",
  "resolver": "1.1.1.1",
  "selectors": ["selector1", "google"],
  "eml_b64": "..."
}
```

Selector priority: custom selectors > aligned selectors from the EML > default list.

### Response (main fields)

```json
{
  "domain": "example.com",
  "resolver": "1.1.1.1",
  "timestamp": "2026-10-19T07:00:00+00:00",
  "eml_selectors_extracted": ["selector1"],
  "selectors_used": ["selector1"],
  "eml": {
    "dkim_signed": true,
    "internal": false,
    "from_domains": ["example.com"],
    "rcpt_domains": ["gmail.com"],
    "dkim_signatures": [{ "s": "selector1", "d": "example.com" }],
    "arc_signatures": [{ "s": "arc-20181011", "d": "gateway.example" }]
  },
  "mx": { "...": "..." },
  "spf": { "...": "..." },
  "dmarc": { "...": "..." },
  "dkim": { "tried": 1, "count": 1, "found": [ "..." ] },
  "overall_status": "ok",
  "elapsed_ms": 120
}
```

`eml` is `null` when no EML is uploaded. `eml_selectors_extracted` contains only selectors from `DKIM-Signature` headers whose `d=` matches `domain`.

### CLI (curl)

```bash
curl -X POST http://localhost:8080/api.php   -F domain=example.com   -F selectors="selector1 selector2"

# With EML file
curl -X POST http://localhost:8080/api.php   -F domain=example.com   -F eml=@mail.eml
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
