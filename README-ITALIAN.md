# Mail DNS Check · Servizio web

Verifica i record SPF, DKIM, DMARC e MX di un dominio con analisi e avvisi visivi, analizza un messaggio reale (`.eml`) per capire se è stato davvero firmato DKIM ed esporta tutto in un report PDF.

🇬🇧 English documentation: [README.md](README.md)

# Demo

https://muninn.ovh/maildns/

Verifica diretta tramite link: https://muninn.ovh/maildns/?domain=example.com

## Requisiti

- Linux con PHP 7.4+ (testato su 8.x), `proc_open` abilitato
- `dig` (`dnsutils` su Debian/Ubuntu, `bind-utils` su RHEL/Rocky)
- Estensione PHP `openssl` (opzionale: fornisce la dimensione esatta delle chiavi RSA; senza, la dimensione viene stimata)
- Un web server con supporto PHP (Apache + mod_php, Nginx + PHP-FPM, oppure `php -S` per i test)

```bash
# Debian/Ubuntu
apt install php-cli php-fpm dnsutils

# RHEL/Rocky
dnf install php php-fpm bind-utils
```

## File

```text
maildns-check/
├── index.html            # interfaccia (italiano + inglese)
├── api.php               # backend (query DNS + analisi)
├── README.md             # documentazione in inglese
├── README-ITALIAN.md     # questo file
├── LICENSE               # GPL-3.0
├── LICENSE_PDFMAKE       # MIT (pdfmake)
└── include/
    ├── pdfmake.min.js    # libreria PDF (inclusa, nessun CDN)
    └── vfs_fonts.js      # font Roboto per pdfmake
```

I file in `include/` sono già presenti. Non serve alcun download a runtime, quindi funziona offline e in ambienti isolati.

## Installazione

### Test rapido (server integrato)

```bash
cd /percorso/di/maildns-check
php -S 0.0.0.0:8080
# apri http://localhost:8080/
```

### Apache

Copia l'intera cartella nella DocumentRoot (ad esempio `/var/www/html/maildns/`). Non serve altra configurazione.

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

### Configurazione

Non serve alcun file di configurazione. I pochi parametri sono costanti in cima ad `api.php`:

| Costante | Default | Significato |
|---|---|---|
| `DEFAULT_RESOLVER` | `1.1.1.1` | Resolver usato se non ne viene indicato uno |
| `DEFAULT_LANG` | `en` | Lingua dei messaggi dell'API se non richiesta né rilevata |
| `DIG_TIMEOUT` / `DIG_TRIES` | `2` / `2` | Secondi per tentativo e tentativi di ogni query `dig` |
| `TIME_BUDGET` | `20` | Secondi massimi di lavoro DNS per richiesta |
| `MAX_CONCURRENT` | `4` | Analisi massime in esecuzione contemporanea (tutti i client) |
| `MAX_PER_IP` | `2` | Analisi massime contemporanee per singolo IP client |
| `RETRY_AFTER` | `5` | Secondi suggeriti al client che riceve HTTP 429 |
| `MAX_SELECTORS` | `100` | Selettori DKIM massimi per richiesta |

Per accettare file `.eml` fino a 5 MB, PHP deve avere `upload_max_filesize` e `post_max_size` ad almeno `5M` (il default di PHP per gli upload è `2M`). Un file più grande viene rifiutato con un errore chiaro.

## Funzionalità

### Lingua

- L'interfaccia è disponibile in **italiano e inglese**.
- La lingua viene **rilevata automaticamente** dal browser (`navigator.languages`): italiano per i browser in italiano, inglese per tutti gli altri.
- Il selettore `IT` / `EN` nell'intestazione ha la precedenza sul rilevamento; la scelta viene ricordata nel browser (`localStorage`).
- `?lang=it` o `?lang=en` nell'URL forza la lingua per quella visita.
- I messaggi dell'analisi sono localizzati dall'API (campo `lang`, oppure header `Accept-Language`), quindi report a video, PDF e JSON usano la stessa lingua.

### Link diretto (`?domain=`)

Aprendo la pagina con il parametro `domain` l'analisi parte subito: comodo per mandare a qualcuno una verifica dal vivo.

```text
https://tuo-host/maildns/?domain=example.com
https://tuo-host/maildns/?domain=example.com&resolver=8.8.8.8
https://tuo-host/maildns/?domain=example.com&selectors=selector1,google
https://tuo-host/maildns/?domain=example.com&lang=it
```

| Parametro | Significato |
|---|---|
| `domain` | Dominio da analizzare (avvia l'analisi) |
| `resolver` | IP del resolver DNS (opzionale) |
| `selectors` | Selettori DKIM custom separati da virgola (opzionale) |
| `lang` | `it` o `en` (opzionale, altrimenti rilevata) |

Dopo ogni analisi la barra degli indirizzi viene aggiornata con il link corrispondente, e nel report compare il riquadro **Condividi questa verifica** con il pulsante per copiarlo.

### Input
- Campo dominio più IP del resolver DNS
- **Upload .eml** (trascinamento o clic). Il dominio viene rilevato dall'header `From`, con ripiego su Sender / Return-Path / Reply-To e, come ultima risorsa, sul `d=` della firma DKIM. Il parsing lato client usa i primi 256 KB.
- I selettori DKIM vengono presi **solo dagli header `DKIM-Signature` il cui `d=` è allineato al dominio analizzato** (stesso dominio, un suo sottodominio o un dominio padre): la chiave si trova in `<s>._domainkey.<d>`, quindi `s=` viene sempre letto insieme al proprio `d=`.
- Gli header `ARC-Message-Signature` / `ARC-Seal` vengono **ignorati** per le ricerche DKIM: sono apposti dai server intermedi (gateway, filtri antispam) e selettore e dominio appartengono a quei server, non al mittente. Vengono mostrati solo come informazione.
- Se l'EML non ha una firma DKIM utilizzabile per il dominio, si usa la lista di selettori di default.
- Il riquadro di upload mostra subito l'esito: selettori trovati, "nessuna firma nel messaggio · posta interna" (blu) oppure "nessuna firma nel messaggio" (rosso).
- Il dominio preso da un EML viene sostituito caricando un altro EML e cancellato rimuovendo l'EML; un dominio digitato a mano non viene mai sovrascritto.
- Opzioni avanzate: selettori DKIM custom. Vengono **verificati insieme** ai selettori trovati nell'EML.

### Analisi del messaggio (EML)
Mostrata come scheda evidenziata in cima al report (e come prima sezione del PDF) quando viene caricato un `.eml`. Distingue la **firma nel messaggio** dalle **chiavi pubblicate nel DNS**:

| Esito | Colore | Significato |
|---|---|---|
| Messaggio firmato DKIM | verde | Firma allineata al dominio, chiave attiva trovata nel DNS |
| Nessuna firma · posta interna | blu | Mittente e tutti i destinatari To/Cc nello stesso dominio: Microsoft 365 e altri provider non firmano DKIM la posta che resta nel tenant |
| Nessuna firma nel messaggio | rosso | Inviato a destinatari esterni senza `DKIM-Signature`; la scheda dice se le chiavi esistono nel DNS (problema di invio) o no (DKIM non configurato) |
| Firma DKIM non allineata | rosso | Firmato solo da altri domini (es. il dominio di un ESP): non conta per l'allineamento DMARC |
| Firmato con una chiave revocata | rosso | Il selettore usato dalla firma ha `p=` vuoto nel DNS: la verifica fallisce presso il destinatario |
| Firma presente, chiave non trovata | giallo | Il selettore usato nella firma non ha una chiave nel DNS: la verifica fallirà presso il destinatario |

L'**allineamento** segue il tag DMARC `adkim` del dominio:

- `exact`: `d=` è identico al dominio del mittente. Sempre allineato.
- `relaxed`: `d=` è un sottodominio o un dominio padre di quello del mittente (es. `d=mail.example.com` per `example.com`). Allineato con il default `adkim=r`, **non** allineato con `adkim=s`.
- Limite: la Public Suffix List non viene usata, quindi due sottodomini "fratelli" (`a.example.com` / `b.example.com`) risultano non allineati anche se l'allineamento relaxed li accetterebbe.

La scheda elenca anche domini di mittente e destinatari, interno/esterno, firme DKIM trovate con il loro allineamento, altre firme non allineate e firme ARC ignorate.

### MX
- Elenco ordinato per priorità
- Avviso se non ci sono record MX o se ce n'è uno solo

### SPF
- Parsing dei meccanismi e del qualificatore `all` finale
- **Segue il modificatore `redirect=`** fino a 5 livelli, con rilevamento dei loop
- Distingue i meccanismi del **record locale** da quelli del **record effettivo** dopo il redirect
- **Conta i DNS lookup sull'intero albero di valutazione** (limite RFC 7208: 10): `include`, `a`, `mx`, `ptr`, `exists` e `redirect`, compresi i termini di ogni `include:` annidato e le forme `a/24` / `mx/24`. Gli include risolti vengono elencati.
- Avvisi per: `+all`, `?all`, lookup > 10, lookup >= 8, record multipli, redirect o include verso un dominio senza SPF, loop
- Riconosce che `all` non serve nel record locale quando è presente `redirect=`

### DMARC
- **Modalità di gestione**: `CNAME` (delegato), `TXT diretto` oppure **conflitto** (entrambi presenti)
- Se è usato un CNAME, risolve il target e ne analizza il record TXT
- **Avviso animato in evidenza** quando viene rilevato un conflitto CNAME + TXT (violazione RFC 1034)
- Parsing dei tag: `p`, `sp`, `pct`, `rua`, `ruf`, `adkim`, `aspf`, `fo`
- `rua` e `ruf` sono mostrati in riquadri dedicati che gestiscono valori multipli

### DKIM
- Lista di default di circa 75 selettori (M365, Google, OVHcloud MX Plan, Fastmail, Hostinger, ESP comuni come Brevo, Mailjet, MailerLite, Constant Contact e Klaviyo, selettori basati su data)
- I selettori che contengono un ID dell'account (es. OVHcloud Exchange / Email Pro `ovhexNNNNNN-selector1`, HubSpot `hs1-<id>`) non si possono indovinare: carica un `.eml` o inseriscili come selettori custom
- Selettori estratti dall'EML caricato (solo `DKIM-Signature` allineate, vedi sopra), uniti a quelli custom
- I selettori delegati via CNAME (es. Microsoft 365 `selectorN-<tenant>._domainkey.<tenant>.<x>.dkim.mail.microsoft`) vengono seguiti correttamente con **una sola query per selettore**: vengono mostrati solo i veri record TXT, il target del CNAME non viene mai scambiato per un valore TXT
- Nota quando esiste un CNAME ma nessuna chiave è pubblicata sul target (normale per il selettore inattivo di Microsoft 365 fino alla prossima rotazione)
- **Stato della chiave** per ogni selettore, mostrato come badge:

  | Stato | Significato |
  |---|---|
  | Attiva | È pubblicata una chiave pubblica |
  | Testing | Chiave pubblicata con il flag `t=y` |
  | Revocata | `p=` è vuoto: secondo RFC 6376 §3.6.1 la chiave è stata revocata |
  | Senza chiave | CNAME presente, nessuna chiave sul target |

- Una chiave revocata è solo **informativa** quando è un vecchio selettore rimasto nel DNS dopo una rotazione, ed è **critica** quando il messaggio caricato è firmato proprio con quel selettore. La sezione passa a warning quando esistono selettori ma nessuno ha una chiave attiva.
- **Dimensione reale della chiave**: il modulo RSA viene letto con OpenSSL (1024, 2048 bit e così via); le chiavi Ed25519 (`k=ed25519`) sono riconosciute e non vengono segnalate come corte.
- **Protezione dai wildcard**: prima viene interrogato un selettore casuale. Se la zona risponde anche per quello (TXT/CNAME wildcard), le risposte identiche vengono scartate, e un TXT che non è un record DKIM (senza `p=`, o con `v=` diverso da `DKIM1`) non viene mai elencato come selettore.

### Report PDF
Il pulsante "Scarica PDF" compare in fondo al report. Il PDF è generato lato client con **pdfmake** direttamente dal JSON dell'API, nella lingua corrente: nessuna rasterizzazione, layout vettoriale pulito e testo che va a capo in modo nativo. Nome file automatico: `maildns-<dominio>-<timestamp>.pdf`.

Il piè di pagina mostra l'indirizzo dell'**istanza che ha generato il report** (preso dall'URL della pagina, niente è scritto nel codice), con link alla stessa verifica.

**Impaginazione attenta ai cambi pagina**:
- Ogni blocco logico (record TXT, avviso, tabella chiave/valore, riga di tag, intero selettore DKIM, riquadro dell'analisi EML) resta su una sola pagina: se non entra nello spazio rimasto passa intero alla pagina successiva.
- I titoli di sezione e le etichette interne restano sempre insieme al blocco che segue, così non rimangono mai soli a fondo pagina.
- pdfmake **scarta** in silenzio un blocco non spezzabile più alto di una pagina. Per evitarlo l'altezza dei blocchi è stimata per eccesso e i blocchi oltre circa il 70% dell'altezza utile restano spezzabili (es. tabelle MX o record SPF molto lunghi); il contenuto non va mai perso.

### Interfaccia
- **Selettore lingua** (IT / EN) e **selettore tema** (Auto / Chiaro / Scuro) nell'intestazione. Auto segue la preferenza del sistema operativo / browser (`prefers-color-scheme`). Entrambe le scelte vengono ricordate nel browser (`localStorage`); il tema è applicato prima del rendering, quindi non c'è alcun lampo del tema sbagliato.
- Quando il server è occupato la pagina mette la richiesta in coda e riprova da sola, mostrando un conto alla rovescia.
- Errore leggibile quando la risposta del server non è JSON (es. pagina di errore di un proxy).
- Footer con copyright e licenza.

## Sicurezza

- Input validati con regex (dominio, selettore, IP del resolver). I selettori devono iniziare con una lettera o una cifra, così un nome passato a `dig` non può mai essere letto come opzione da riga di comando.
- `dig` invocato tramite `proc_open` con argomenti passati come **array**. Nessuna shell injection
- **Gli errori DNS non vengono mai scambiati per "record non trovato"**: timeout, `SERVFAIL`/`REFUSED` e `dig` mancante sono riportati come tali (stato della sezione `N/A`), e un resolver irraggiungibile interrompe subito la richiesta con HTTP 502.
- **Limiti anti-abuso, senza toccare il web server**:
  - al massimo `MAX_CONCURRENT` analisi contemporanee in totale e `MAX_PER_IP` per IP client (file di lock), così un solo client non può occupare tutti gli slot; le richieste in più ricevono HTTP 429 con `Retry-After`
  - **coda lato client**: su HTTP 429 la pagina mostra "sei in coda", attende il tempo di `Retry-After` e riprova da sola per un massimo di 60 secondi. Nessun worker PHP resta occupato durante l'attesa. La coda non è ordinata: passa chi riprova per primo quando si libera uno slot
  - il limite per IP usa solo `REMOTE_ADDR` (`X-Forwarded-For` è falsificabile) e raggruppa i client IPv6 per /64. Dietro un reverse proxy su un altro host tutti i visitatori condividono l'indirizzo del proxy: in quel caso porta `MAX_PER_IP` al valore di `MAX_CONCURRENT`
  - al massimo `TIME_BUDGET` secondi di lavoro DNS per richiesta; i selettori non verificati vengono segnalati
  - il resolver viene sondato con una query prima di iniziare l'analisi
  - limite di 100 selettori per richiesta, una query DNS per selettore
  - l'albero degli include SPF viene percorso con un tetto a profondità e query
- Limite di 5 MB per i file `.eml` (multipart e JSON); errori di upload e richieste troppo grandi restituiscono un errore chiaro invece di essere ignorati
- L'input JSON è controllato nei tipi
- Il parsing dell'EML è limitato al blocco degli header; i valori estratti dal messaggio sono validati prima dell'uso e sottoposti a escape prima della visualizzazione
- `X-Content-Type-Options: nosniff`, `Cache-Control: no-store`

Resta a tuo carico: il campo resolver accetta qualsiasi indirizzo IP, anche privato (utile sulle reti interne). Su un'istanza pubblica valuta un rate limit a livello di web server o firewall.

## API

`POST /api.php`

### Form multipart

```text
domain=example.com
resolver=1.1.1.1                # opzionale
selectors=selector1, google     # opzionale
lang=it                         # opzionale: it | en
eml=@/percorso/di/mail.eml      # opzionale
```

### JSON

```json
{
  "domain": "example.com",
  "resolver": "1.1.1.1",
  "selectors": ["selector1", "google"],
  "lang": "it",
  "eml_b64": "..."
}
```

Selettori: quelli custom e quelli allineati presi dall'EML vengono uniti; la lista di default si usa solo se mancano entrambi.

Lingua: campo `lang` > header `Accept-Language` > `DEFAULT_LANG`.

### Risposta (campi principali)

```json
{
  "domain": "example.com",
  "resolver": "1.1.1.1",
  "lang": "it",
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

- `eml` è `null` se non viene caricato un EML. `alignment` vale `exact`, `relaxed` o `none`.
- `dkim.found[].state` vale `active`, `testing`, `revoked` o `no_key`.
- Lo `status` delle sezioni e `overall_status` valgono `ok`, `warning`, `critical` o `unknown` (errori DNS).

### Errori

Gli errori sono restituiti come `{"error": "..."}` nella lingua della richiesta.

| HTTP | Causa |
|---|---|
| 400 | Dominio, resolver, JSON o upload non validi |
| 405 | Metodo diverso da POST |
| 413 | EML o richiesta troppo grandi |
| 429 | Troppe analisi in corso, in totale (`"scope": "global"`) o dallo stesso IP (`"scope": "ip"`). Il corpo contiene `retry_after` (secondi), inviato anche come header `Retry-After`: attendi e riprova |
| 500 | `dig` mancante o `proc_open` disabilitato |
| 502 | Il resolver non risponde, oppure risponde `SERVFAIL`/`REFUSED` |

### CLI (curl)

```bash
curl -X POST http://localhost:8080/api.php -F domain=example.com -F selectors="selector1 selector2"

# Con file EML, messaggi in italiano
curl -X POST http://localhost:8080/api.php -F domain=example.com -F lang=it -F eml=@mail.eml
```

> Suggerimento: per verificare se la posta in uscita è davvero firmata DKIM, carica un messaggio inviato a un destinatario **esterno**. La posta tra caselle dello stesso dominio di solito non viene firmata da Microsoft 365.

## Crediti e licenze

Questo progetto include software di terze parti:

- **[pdfmake](https://github.com/bpampuch/pdfmake)** v0.2.10 di Bartek Pampuch e contributori, distribuito con licenza **MIT**. Generazione del report PDF lato client.
  - File: `include/pdfmake.min.js`, `include/vfs_fonts.js`
  - Sito: [http://pdfmake.org](http://pdfmake.org)
- Font **Roboto** (incluso nel vfs di pdfmake), Google Fonts, licenza Apache 2.0.

Il resto del codice è originale.

## Licenza

Questo progetto è rilasciato con licenza **GNU General Public License v3.0** (GPL-3.0). Vedi [LICENSE](LICENSE) oppure <https://www.gnu.org/licenses/gpl-3.0.html>.

I componenti di terze parti mantengono le rispettive licenze (vedi sopra).

## Autore

https://github.com/Leproide
