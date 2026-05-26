# Mail DNS Check · Web service

Check a domain's SPF, DKIM, DMARC, and MX records with analysis and visual alerts, plus PDF report generation.

# Demo

https://muninn.ovh/maildns/

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
- **.eml upload**: automatically detects the domain (From header, fallback to Sender / Return-Path / Reply-To, last resort `d=` from the DKIM signature) and DKIM selectors (`s=` from `DKIM-Signature` and `ARC-Message-Signature`). Drag and drop or click to select. Client-side parsing uses the first 256 KB.
- Advanced options: custom DKIM selectors

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
- Selectors extracted from the uploaded EML file
- Custom selectors via text field
- For each selector: tag parsing, key size estimation (1024 vs 2048 bit), testing flag (`t=y`), revocations (`p=` empty)

### PDF report
The "Download PDF" button appears at the bottom of the report. The PDF is generated client-side with **pdfmake** directly from the API JSON: no rasterization, no blank pages, clean vector layout, and native text wrapping. Automatic filename: `maildns-<domain>-<timestamp>.pdf`.

## Security

- Inputs validated with regex (domain, selector, resolver IP)
- `dig` invoked through `proc_open` with arguments passed as an **array**. No shell injection
- Limit of 100 selectors per request
- Limit of 5 MB for `.eml` files
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

### CLI (curl)

```bash
curl -X POST http://localhost:8080/api.php   -F domain=example.com   -F selectors="selector1 selector2"

# With EML file
curl -X POST http://localhost:8080/api.php   -F domain=example.com   -F eml=@mail.eml
```

## Credits and licenses

This project includes third-party software:

- **[pdfmake](https://github.com/bpampuch/pdfmake)** v0.2.10 by Bartek Pampuch and contributors, distributed under the **MIT** license. Client-side PDF report generation.
  - Files: `include/pdfmake.min.js`, `include/vfs_fonts.js`
  - Website: [http://pdfmake.org](http://pdfmake.org)
- **Roboto** font (included in pdfmake's vfs), Google Fonts, licensed under Apache 2.0.

The rest of the code is original.
