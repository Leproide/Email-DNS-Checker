<?php
/**
 * Mail DNS Check
 * Copyright (C) 2026 Leproide
 * Author: https://github.com/Leproide
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 */

/**
 * maildns-check API
 * Single endpoint: POST JSON { domain, selectors?, resolver?, lang?, eml_b64? }
 * or multipart form with an optional 'eml' file.
 */

declare(strict_types=1);

header('Content-Type: application/json; charset=utf-8');
header('X-Content-Type-Options: nosniff');
header('Cache-Control: no-store');

// ---------- CONFIG ----------
const DEFAULT_RESOLVER = '1.1.1.1';
const DEFAULT_LANG     = 'en';      // language of API messages when none is requested/detected
const DIG_TIMEOUT      = 2;         // seconds per try
const DIG_TRIES        = 2;
const TIME_BUDGET      = 20.0;      // max seconds of DNS work per request (DoS guard)
const MAX_CONCURRENT   = 4;         // max analyses running at the same time, all clients (DoS guard)
const MAX_PER_IP       = 2;         // max analyses running at the same time for one client IP
const IP_BUCKETS       = 512;       // client IPs are hashed into this many lock buckets (bounds the lock files)
const RETRY_AFTER      = 5;         // seconds suggested to a client that got HTTP 429
const MAX_SELECTORS    = 100;
const MAX_EML_BYTES    = 5000000;   // 5 MB
const SPF_MAX_QUERIES  = 30;        // max TXT queries spent walking the SPF include tree

// Well-known DKIM selectors per provider, used when the user gives none.
const DEFAULT_SELECTORS = [
    // generic
    'default','mail','dkim','email','key1','smtp','dk',
    // Microsoft 365 / Exchange
    'selector1','selector2',
    // Google Workspace
    'google',
    // OVHcloud MX Plan / Zimbra (CNAME to *.dkim.mail.ovh.net).
    // Exchange / Email Pro use ovhexNNNNNN-selectorN: per-service ID, cannot be listed.
    'ovhmo-selector-1','ovhmo-selector-2',
    // Fastmail (CNAME to *.dkim.fmhosted.com; mesmtp = domains hosted before 2018)
    'fm1','fm2','fm3','mesmtp',
    // Hostinger Email (CNAME to *.dkim.mail.hostinger.com)
    'hostingermail-a','hostingermail-b','hostingermail-c',
    // Apple iCloud
    'sig1',
    // ProtonMail
    'protonmail','protonmail2','protonmail3',
    // Zoho
    'zoho','zmail',
    // Mailchimp / Mandrill
    'k1','k2','k3','mandrill',
    // SendGrid / Twilio
    's1','s2','smtpapi','m1',
    // Mailgun
    'mg','pic','krs','mta',
    // Amazon SES
    'amazonses',
    // Postmark
    'pm',
    // Brevo / Sendinblue (brevo1/brevo2 = current CNAMEs; legacy TXT 'mail' is in the generic group)
    'brevo1','brevo2','mail1','mail2',
    // Mailjet
    'mailjet',
    // MailerLite (litesrv = new platform, ml = Classic)
    'litesrv','ml',
    // Constant Contact
    'ctct1','ctct2',
    // SendPulse
    'sendpulse',
    // Klaviyo branded sending domain (km = marketing, kt = transactional, kl/kl1/kl2 = legacy)
    'km1','km2','kt1','kt2','kl','kl1','kl2',
    // ActiveCampaign / ConvertKit / Drip
    'dkim2','ck1','drip',
    // Zendesk
    'zendesk1','zendesk2',
    // AWeber
    'aweber_key_a','aweber_key_b','aweber_key_c',
    // Cisco
    'cisco1','cisco2',
    // legacy
    's2048','s1024',
    // date-based (rotation)
    '20230601','20240101','20240601','20250101','20250601','20260101',
];

// ---------- I18N ----------
// API messages in Italian and English. Placeholders use sprintf syntax.
const MSG = [
    'err_only_post' => ['it' => 'Solo POST', 'en' => 'Only POST'],
    'err_bad_json'  => ['it' => 'JSON non valido', 'en' => 'Invalid JSON'],
    'err_domain'    => ['it' => 'Dominio mancante o non valido', 'en' => 'Missing or invalid domain'],
    'err_resolver'  => ['it' => 'Resolver non valido (IP atteso)', 'en' => 'Invalid resolver (IP address expected)'],
    'err_eml_big'   => ['it' => 'File EML troppo grande (max 5 MB)', 'en' => 'EML file too large (max 5 MB)'],
    'err_upload'    => ['it' => 'Caricamento del file EML non riuscito (codice %d). Se il file supera il limite del server (upload_max_filesize) riducilo o alza il limite.',
                        'en' => 'EML upload failed (code %d). If the file exceeds the server limit (upload_max_filesize), shrink it or raise the limit.'],
    'err_post_big'  => ['it' => 'Richiesta troppo grande per il server (post_max_size).', 'en' => 'Request too large for the server (post_max_size).'],
    'err_busy'      => ['it' => 'Troppe analisi in corso, riprova tra qualche secondo.', 'en' => 'Too many analyses in progress, retry in a few seconds.'],
    'err_busy_ip'   => ['it' => 'Hai già troppe analisi in corso dal tuo indirizzo, attendi che finiscano.', 'en' => 'Too many analyses already running from your address, wait for them to finish.'],
    'err_dig'       => ['it' => 'Impossibile eseguire dig sul server (comando mancante o proc_open disabilitato).',
                        'en' => 'Cannot run dig on the server (command missing or proc_open disabled).'],
    'err_resolver_down'   => ['it' => 'Il resolver DNS %s non risponde.', 'en' => 'DNS resolver %s is not answering.'],
    'err_resolver_status' => ['it' => 'Il resolver DNS %s ha risposto %s per il dominio: resolver non utilizzabile oppure DNS del dominio non funzionante (es. DNSSEC non valido).',
                              'en' => 'DNS resolver %s answered %s for the domain: resolver not usable, or the domain DNS is broken (e.g. invalid DNSSEC).'],

    'dns_error'     => ['it' => 'Query DNS fallita per %s (%s): risultato non determinabile, riprova.',
                        'en' => 'DNS query failed for %s (%s): result cannot be determined, retry.'],
    'dns_timeout'   => ['it' => 'nessuna risposta', 'en' => 'no answer'],
    'dns_budget'    => ['it' => 'tempo massimo superato', 'en' => 'time budget exceeded'],

    'mx_none'       => ['it' => 'Nessun record MX trovato: il dominio non può ricevere posta.', 'en' => 'No MX record found: the domain cannot receive mail.'],
    'mx_single'     => ['it' => 'Un solo MX: nessuna ridondanza in caso di failure del primario.', 'en' => 'Only one MX: no redundancy if the primary fails.'],

    'spf_multiple'  => ['it' => 'Più di un record SPF (v=spf1) presente. RFC 7208 vieta record multipli, gli MTA li considereranno PermError.',
                        'en' => 'More than one SPF record (v=spf1) found. RFC 7208 forbids multiple records, MTAs will treat them as PermError.'],
    'spf_none'      => ['it' => 'Nessun record SPF trovato per il dominio.', 'en' => 'No SPF record found for the domain.'],
    'spf_loop'      => ['it' => 'Loop nella catena di redirect SPF: %s già visitato.', 'en' => 'Loop in the SPF redirect chain: %s already visited.'],
    'spf_too_deep'  => ['it' => 'Catena di redirect SPF troppo profonda (oltre %d livelli).', 'en' => 'SPF redirect chain too deep (more than %d levels).'],
    'spf_redirect_no_spf' => ['it' => 'Redirect SPF a %s ma il target non ha record v=spf1 (PermError).', 'en' => 'SPF redirect to %s but the target has no v=spf1 record (PermError).'],
    'spf_redirect_multi'  => ['it' => 'Il target redirect %s ha più record v=spf1 (PermError).', 'en' => 'Redirect target %s has multiple v=spf1 records (PermError).'],
    'spf_lookups_over'    => ['it' => 'Superato il limite di 10 DNS lookup (%d, include annidati compresi). Risultato SPF sarà PermError.',
                              'en' => 'The limit of 10 DNS lookups is exceeded (%d, nested includes counted). The SPF result will be PermError.'],
    'spf_lookups_near'    => ['it' => 'Vicino al limite di 10 DNS lookup (%d/10, include annidati compresi). Considera flattening.',
                              'en' => 'Close to the limit of 10 DNS lookups (%d/10, nested includes counted). Consider flattening.'],
    'spf_lookups_capped'  => ['it' => 'Albero degli include SPF troppo grande: conteggio dei lookup interrotto, il valore reale è maggiore o uguale a quello mostrato.',
                              'en' => 'SPF include tree too large: lookup count stopped, the real value is greater than or equal to the one shown.'],
    'spf_include_no_spf'  => ['it' => 'include:%s punta a un dominio senza record v=spf1 (PermError).', 'en' => 'include:%s points to a domain without a v=spf1 record (PermError).'],
    'spf_include_loop'    => ['it' => 'Loop negli include SPF: %s include sé stesso (PermError).', 'en' => 'Loop in SPF includes: %s includes itself (PermError).'],
    'spf_include_macro'   => ['it' => 'Il termine SPF verso "%s" usa macro o un nome non risolvibile staticamente: contato come 1 lookup, contenuto non analizzato.',
                              'en' => 'The SPF term targeting "%s" uses macros or a name that cannot be resolved statically: counted as 1 lookup, content not analysed.'],
    'spf_include_unresolved' => ['it' => 'Impossibile risolvere il record SPF di %s (errore DNS): conteggio dei lookup incompleto.',
                                 'en' => 'Cannot resolve the SPF record of %s (DNS error): lookup count is incomplete.'],
    'spf_plus_all'  => ['it' => 'Qualificatore "+all" presente: chiunque può inviare email per il dominio. Configurazione INSICURA.',
                        'en' => 'Qualifier "+all" present: anyone can send mail for the domain. INSECURE configuration.'],
    'spf_neutral_all' => ['it' => 'Qualificatore "?all" (neutral): nessuna policy effettiva.', 'en' => 'Qualifier "?all" (neutral): no effective policy.'],
    'spf_no_all_redirect' => ['it' => 'Manca il meccanismo "all" anche nel record effettivo dopo il redirect: comportamento non definito sui mittenti non listati.',
                              'en' => 'The "all" mechanism is missing even in the effective record after the redirect: undefined behaviour for unlisted senders.'],
    'spf_no_all'    => ['it' => 'Manca il meccanismo "all" finale: comportamento non definito sui mittenti non listati.',
                        'en' => 'The final "all" mechanism is missing: undefined behaviour for unlisted senders.'],
    'spf_via_redirect' => ['it' => 'Policy SPF risolta tramite redirect a %s. Il meccanismo "all" non va aggiunto nel record locale, perché il redirect delega l\'intera policy al target.',
                           'en' => 'SPF policy resolved through a redirect to %s. Do not add "all" to the local record: the redirect delegates the whole policy to the target.'],

    'dmarc_conflict' => ['it' => 'CONFLITTO: presenti SIA CNAME SIA TXT sulla stessa label _dmarc. RFC 1034 vieta CNAME coesistente con altri record sullo stesso owner. I resolver autoritativi rifiuteranno la zona o ignoreranno uno dei due. Configurazione da correggere SUBITO.',
                         'en' => 'CONFLICT: both a CNAME and a TXT record exist on the same _dmarc label. RFC 1034 forbids a CNAME next to other records on the same owner. Authoritative servers will reject the zone or ignore one of them. Fix this configuration NOW.'],
    'dmarc_cname_no_record' => ['it' => 'Il CNAME punta a %s ma non restituisce alcun record v=DMARC1 valido.', 'en' => 'The CNAME points to %s but no valid v=DMARC1 record is returned.'],
    'dmarc_none'     => ['it' => 'Nessun record DMARC trovato (né TXT né CNAME su _dmarc).', 'en' => 'No DMARC record found (neither TXT nor CNAME on _dmarc).'],
    'dmarc_multiple' => ['it' => 'Più record DMARC presenti. RFC 7489 prevede un solo record, gli MTA ignoreranno tutti.', 'en' => 'Multiple DMARC records found. RFC 7489 allows a single record, MTAs will ignore all of them.'],
    'dmarc_p_invalid' => ['it' => 'Tag p= mancante o non valido (deve essere none|quarantine|reject).', 'en' => 'Tag p= missing or invalid (must be none|quarantine|reject).'],
    'dmarc_p_none'   => ['it' => 'Policy p=none: solo monitoring, NON blocca le mail di phishing. Pianifica passaggio a quarantine/reject.',
                         'en' => 'Policy p=none: monitoring only, it does NOT block phishing mail. Plan the move to quarantine/reject.'],
    'dmarc_p_quarantine' => ['it' => 'Policy p=quarantine: protezione media. Per il massimo, considera p=reject.', 'en' => 'Policy p=quarantine: medium protection. For the maximum, consider p=reject.'],
    'dmarc_pct'      => ['it' => 'pct=%d: la policy si applica solo al %d%% dei messaggi non allineati.', 'en' => 'pct=%d: the policy applies to only %d%% of non-aligned messages.'],
    'dmarc_no_rua'   => ['it' => 'Manca il tag rua=, non riceverai i report aggregati, impossibile monitorare.', 'en' => 'Tag rua= is missing: you will not receive aggregate reports, monitoring is impossible.'],
    'dmarc_sp_inherit' => ['it' => 'sp= non specificato: i sottodomini ereditano da p=reject.', 'en' => 'sp= not set: subdomains inherit p=reject.'],
    'dmarc_strict'   => ['it' => 'Allineamento strict (adkim/aspf=s) attivo, più severo del default relaxed.', 'en' => 'Strict alignment (adkim/aspf=s) enabled, stricter than the relaxed default.'],

    'dkim_revoked'   => ['it' => 'Chiave REVOCATA (p= vuoto, RFC 6376 §3.6.1): le firme fatte con questo selettore non sono più verificabili. Normale per un vecchio selettore dopo una rotazione; se non serve più il record si può rimuovere.',
                         'en' => 'Key REVOKED (empty p=, RFC 6376 §3.6.1): signatures made with this selector can no longer be verified. Normal for an old selector after a rotation; the record can be removed if no longer needed.'],
    'dkim_revoked_used' => ['it' => 'Chiave REVOCATA (p= vuoto) ma il messaggio caricato è firmato proprio con questo selettore: la verifica DKIM fallisce presso i destinatari. Attiva un nuovo selettore sul server di invio o ripubblica la chiave.',
                            'en' => 'Key REVOKED (empty p=) but the uploaded message is signed with this very selector: DKIM verification fails at the recipients. Enable a new selector on the sending server or publish the key again.'],
    'dkim_testing'   => ['it' => 'Flag t=y: DKIM in modalità testing, i verifier devono ignorare i failure.', 'en' => 'Flag t=y: DKIM in testing mode, verifiers must ignore failures.'],
    'dkim_weak'      => ['it' => 'Chiave RSA da %d bit: sotto i 1024 bit è deprecata e rifiutata da molti destinatari.', 'en' => '%d-bit RSA key: below 1024 bits it is deprecated and rejected by many receivers.'],
    'dkim_1024'      => ['it' => 'Chiave RSA da %d bit: funzionante ma 2048 raccomandato.', 'en' => '%d-bit RSA key: it works, but 2048 is recommended.'],
    'dkim_weak_len'  => ['it' => 'Chiave probabilmente inferiore a 1024 bit (lunghezza base64 %d), deprecata.', 'en' => 'Key probably shorter than 1024 bits (base64 length %d), deprecated.'],
    'dkim_1024_len'  => ['it' => 'Chiave di circa 1024 bit: funzionante ma 2048 raccomandato.', 'en' => 'Key of about 1024 bits: it works, but 2048 is recommended.'],
    'dkim_bad_key'   => ['it' => 'Il valore di p= non è base64 valido: la chiave non è utilizzabile.', 'en' => 'The value of p= is not valid base64: the key cannot be used.'],
    'dkim_cname_no_key' => ['it' => 'CNAME presente ma nessuna chiave DKIM pubblicata sul target. Normale per il selettore inattivo di Microsoft 365 (verrà popolato alla prossima rotazione).',
                            'en' => 'CNAME present but no DKIM key is published at the target. Normal for the inactive Microsoft 365 selector (it gets populated at the next rotation).'],
    'dkim_wildcard'  => ['it' => 'Rilevato un record wildcard sotto _domainkey.%s: le risposte identiche al wildcard sono state scartate perché non sono selettori reali.',
                         'en' => 'A wildcard record was detected under _domainkey.%s: answers identical to the wildcard were discarded because they are not real selectors.'],
    'dkim_truncated' => ['it' => 'Tempo massimo di analisi superato: %d selettori non sono stati verificati.', 'en' => 'Analysis time budget exceeded: %d selectors were not checked.'],
    'dkim_dns_errors' => ['it' => '%d query DKIM non hanno avuto risposta dal resolver: l\'elenco dei selettori può essere incompleto.',
                          'en' => '%d DKIM queries got no answer from the resolver: the selector list may be incomplete.'],
    'dkim_no_active' => ['it' => 'Selettori trovati, ma nessuno ha una chiave attiva (revocata o non pubblicata).', 'en' => 'Selectors found, but none has an active key (revoked or not published).'],
];

$LANG = DEFAULT_LANG;

/** Translate a message key into the request language. */
function t(string $key, ...$args): string {
    global $LANG;
    $s = MSG[$key][$LANG] ?? MSG[$key]['en'] ?? $key;
    return $args ? vsprintf($s, $args) : $s;
}

/** Request language: explicit value > Accept-Language header > DEFAULT_LANG. */
function pick_lang($explicit): string {
    if (is_string($explicit)) {
        $e = strtolower(substr(trim($explicit), 0, 2));
        if ($e === 'it' || $e === 'en') return $e;
    }
    $al = (string)($_SERVER['HTTP_ACCEPT_LANGUAGE'] ?? '');
    foreach (explode(',', $al) as $part) {
        $p = strtolower(substr(trim($part), 0, 2));
        if ($p === 'it' || $p === 'en') return $p;
    }
    return DEFAULT_LANG;
}

// ---------- UTILS ----------
function bail(int $code, string $msg, array $extra = []): void {
    http_response_code($code);
    echo json_encode(['error' => $msg] + $extra, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    exit;
}

function ends_with(string $s, string $suffix): bool {
    $l = strlen($suffix);
    return $l === 0 || ($l <= strlen($s) && substr($s, -$l) === $suffix);
}

function is_valid_domain(string $d): bool {
    if (strlen($d) > 253) return false;
    return (bool)preg_match('/^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/i', $d);
}

/**
 * DNS name as found inside SPF records (include:/redirect= targets): like a
 * domain, but labels may contain underscores (e.g. _spf.google.com). Labels
 * never start with "-", so the name is safe as a dig argument.
 */
function is_valid_dns_name(string $d): bool {
    if (strlen($d) > 253) return false;
    return (bool)preg_match('/^([a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?\.)+[a-z]{2,63}$/i', $d);
}

/**
 * A selector must start with a letter or digit: besides being what RFC 6376
 * requires, it guarantees the name handed to dig can never start with "-"
 * and be parsed as a command-line option.
 */
function is_valid_selector(string $s): bool {
    return (bool)preg_match('/^[a-zA-Z0-9][a-zA-Z0-9_\-\.]{0,62}$/', $s);
}

function is_valid_resolver(string $r): bool {
    return (bool)filter_var($r, FILTER_VALIDATE_IP);
}

function worst_status(array $issues): string {
    foreach ($issues as $i) if ($i['level'] === 'critical') return 'critical';
    foreach ($issues as $i) if ($i['level'] === 'warning')  return 'warning';
    return 'ok';
}

// ---------- DoS GUARDS ----------
$T_START = microtime(true);

/** Seconds of DNS work still allowed for this request. */
function budget_left(): float {
    global $T_START;
    return TIME_BUDGET - (microtime(true) - $T_START);
}

/**
 * Takes one of $max slots named $name using non-blocking file locks.
 * Returns the lock handle (kept open until the script ends, the lock is
 * released automatically even if the script dies), true when locking is not
 * available on this host (no limit applied), or null when all slots are busy.
 */
function acquire_slot(string $name, int $max) {
    $dir = sys_get_temp_dir();
    $opened = false;
    for ($i = 0; $i < $max; $i++) {
        $fh = @fopen($dir.'/maildns-check-'.$name.'-'.$i.'.lock', 'c');
        if ($fh === false) continue;
        $opened = true;
        if (flock($fh, LOCK_EX | LOCK_NB)) return $fh;
        fclose($fh);
    }
    return $opened ? null : true;
}

/**
 * Lock bucket of the client, for the per-IP limit; null when the address is
 * unknown (CLI). Only REMOTE_ADDR is used: X-Forwarded-For can be forged by
 * the client. IPv6 clients are grouped by /64, since one host owns the whole
 * prefix. Hashing into IP_BUCKETS buckets keeps the number of lock files
 * bounded; two addresses in the same bucket simply share the limit.
 */
function client_bucket(): ?string {
    $bin = @inet_pton((string)($_SERVER['REMOTE_ADDR'] ?? ''));
    if ($bin === false) return null;
    if (strlen($bin) === 16) {
        $bin = (substr($bin, 0, 12) === str_repeat("\0", 10)."\xff\xff")
            ? substr($bin, 12)      // IPv4-mapped IPv6
            : substr($bin, 0, 8);   // /64 prefix
    }
    return (string)(crc32($bin) % IP_BUCKETS);
}

// ---------- DNS ----------
/** Failed queries of this request: [['name'=>..., 'type'=>..., 'error'=>...], ...] */
$DNS_ERRORS = [];

/**
 * Runs one dig query and returns
 *   ['ok'=>bool, 'status'=>'NOERROR'|'NXDOMAIN'|..., 'error'=>'', 'records'=>[['owner','type','rdata'],...]]
 *
 * - arguments are passed to proc_open as an array: no shell, no injection;
 * - 'ok' is true only when the resolver really answered (NOERROR/NXDOMAIN):
 *   timeouts, SERVFAIL/REFUSED and a missing dig are reported as errors and
 *   never mistaken for "record not found";
 * - the full answer section is parsed (not `+short`), so a CNAME can be told
 *   apart from the TXT reached through it;
 * - answers are cached per request.
 */
function dig_query(string $resolver, string $type, string $name): array {
    global $DNS_ERRORS;
    static $cache = [];
    $key = $type.'|'.strtolower($name);
    if (isset($cache[$key])) return $cache[$key];

    $res = ['ok' => false, 'status' => '', 'error' => '', 'records' => []];
    $fail = function (string $err) use (&$res, $name, $type): array {
        global $DNS_ERRORS;
        $res['error'] = $err;
        $DNS_ERRORS[] = ['name' => $name, 'type' => $type, 'error' => $err];
        return $res;
    };

    if (budget_left() <= 0) return $fail('budget'); // not cached on purpose

    if (!function_exists('proc_open')) return $cache[$key] = $fail('exec');
    $cmd = [
        'dig', '@'.$resolver, '+noall', '+comments', '+answer',
        '+time='.DIG_TIMEOUT, '+tries='.DIG_TRIES,
        $type, $name,
    ];
    // stderr goes to a pipe too (not to a /dev/null file): opening a file
    // here fails under open_basedir and would make every query fail.
    $desc = [1 => ['pipe', 'w'], 2 => ['pipe', 'w']];
    $proc = @proc_open($cmd, $desc, $pipes);
    if (!is_resource($proc)) return $cache[$key] = $fail('exec');
    $out = (string)stream_get_contents($pipes[1]);
    stream_get_contents($pipes[2]); // drained and discarded
    fclose($pipes[1]);
    fclose($pipes[2]);
    $exit = proc_close($proc);

    if ($exit === 127 || $exit === 126) return $cache[$key] = $fail('exec');

    if (!preg_match('/->>HEADER<<-.*?status:\s*([A-Z0-9]+)/', $out, $m)) {
        // no DNS header at all: the resolver never answered
        return $cache[$key] = $fail('timeout');
    }
    $res['status'] = $m[1];
    if ($m[1] !== 'NOERROR' && $m[1] !== 'NXDOMAIN') {
        return $cache[$key] = $fail($m[1]);
    }
    $res['ok'] = true;

    // NXDOMAIN answers are parsed too: a CNAME whose target does not exist
    // comes back as NXDOMAIN with the CNAME in the answer section.
    foreach (explode("\n", $out) as $line) {
        $line = trim($line);
        if ($line === '' || $line[0] === ';') continue;
        // format: owner TTL CLASS TYPE rdata...
        if (preg_match('/^(\S+)\s+\d+\s+IN\s+(\S+)\s+(.+)$/i', $line, $mm)) {
            $res['records'][] = [
                'owner' => rtrim(strtolower($mm[1]), '.'),
                'type'  => strtoupper($mm[2]),
                'rdata' => trim($mm[3]),
            ];
        }
    }
    return $cache[$key] = $res;
}

/** Human readable reason of a failed query. */
function dns_reason(string $err): string {
    if ($err === 'timeout') return t('dns_timeout');
    if ($err === 'budget')  return t('dns_budget');
    return $err;
}

function dns_fail_issue(string $name, array $q): array {
    return ['level' => 'critical', 'msg' => t('dns_error', $name, dns_reason($q['error']))];
}

/**
 * TXT rdata as printed by dig ("part one" "part two"): joins the segments
 * and undoes the presentation escapes (\" \\ \DDD).
 */
function txt_value(string $rdata): string {
    if (!preg_match_all('/"((?:[^"\\\\]|\\\\.)*)"/', $rdata, $m)) return $rdata;
    $joined = implode('', $m[1]);
    return (string)preg_replace_callback('/\\\\(\d{3}|.)/', function ($x) {
        return (strlen($x[1]) === 3 && ctype_digit($x[1])) ? chr((int)$x[1] & 0xFF) : $x[1];
    }, $joined);
}

/** All TXT values of an answer (whatever their owner, i.e. CNAMEs are followed). */
function txt_values(array $q): array {
    $out = [];
    foreach ($q['records'] as $r) if ($r['type'] === 'TXT') $out[] = txt_value($r['rdata']);
    return $out;
}

// ---------- SPF ----------
function spf_records(string $resolver, string $domain): array {
    $q   = dig_query($resolver, 'TXT', $domain);
    $txt = txt_values($q);
    $spf = [];
    foreach ($txt as $r) if (preg_match('/^v=spf1(\s|$)/i', $r)) $spf[] = $r;
    return ['ok' => $q['ok'], 'error' => $q['error'], 'txt' => $txt, 'spf' => $spf];
}

/**
 * Counts the DNS lookups an SPF evaluation of $record needs (RFC 7208 §4.6.4):
 * include, a, mx, ptr, exists and redirect each cost one, and the terms of
 * every included/redirected record count too, recursively.
 * $path holds the domains on the current branch (loop detection).
 */
function spf_count_lookups(string $resolver, string $record, array $path, int $depth, array &$ctx): int {
    $n = 0;
    $hasAll = false;
    $redirect = null;
    $tokens = preg_split('/\s+/', trim($record)) ?: [];
    array_shift($tokens); // v=spf1
    foreach ($tokens as $t) {
        if ($t === '') continue;
        $bare = strtolower(ltrim($t, '+-~?'));
        if ($bare === 'all') { $hasAll = true; continue; }
        // a, a:host, a/24, a:host/24 (same for mx), ptr, ptr:host, exists:host
        if (preg_match('/^(a|mx)([:\/].*)?$/', $bare) || preg_match('/^ptr(:.*)?$/', $bare) || strpos($bare, 'exists:') === 0) {
            $n++;
            continue;
        }
        if (preg_match('/^include:(.+)$/', $bare, $m)) {
            $n++;
            $n += spf_follow($resolver, $m[1], $path, $depth, $ctx, true);
            continue;
        }
        if (preg_match('/^redirect=(.+)$/', $bare, $m)) $redirect = $m[1];
    }
    // redirect= is only evaluated when no mechanism matched, i.e. never if "all" is present
    if ($redirect !== null && !$hasAll) {
        $n++;
        $n += spf_follow($resolver, $redirect, $path, $depth, $ctx, false);
    }
    return $n;
}

function spf_follow(string $resolver, string $target, array $path, int $depth, array &$ctx, bool $isInclude): int {
    $target = rtrim($target, '.');
    $note = function (string $level, string $key) use (&$ctx, $target, $isInclude): void {
        // problems on the redirect chain are already reported by analyze_spf()
        if ($isInclude) $ctx['notes'][$key.'|'.$target] = ['level' => $level, 'msg' => t($key, $target)];
    };
    if (strpos($target, '%') !== false || !is_valid_dns_name($target)) { $note('info', 'spf_include_macro'); return 0; }
    if (isset($path[$target])) { $note('critical', 'spf_include_loop'); return 0; }
    if ($depth >= 10 || $ctx['queries'] >= SPF_MAX_QUERIES) { $ctx['capped'] = true; return 0; }
    $ctx['queries']++;
    $r = spf_records($resolver, $target);
    if (!$r['ok']) { $ctx['notes']['unres|'.$target] = ['level' => 'warning', 'msg' => t('spf_include_unresolved', $target)]; return 0; }
    if ($isInclude) $ctx['includes'][$target] = true;
    if (!$r['spf']) { $note('critical', 'spf_include_no_spf'); return 0; }
    $path[$target] = true;
    return spf_count_lookups($resolver, $r['spf'][0], $path, $depth + 1, $ctx);
}

// Follows the redirect= modifier (RFC 7208 §6.1): redirect delegates the WHOLE
// policy to the target, so "all" is not needed in the local record and the
// effective "all" is the one of the final target.
function analyze_spf(string $resolver, string $domain): array {
    $first = spf_records($resolver, $domain);
    $txt = $first['txt'];
    $spf = $first['spf'];

    $res = [
        'found'         => count($spf) > 0,
        'records'       => $spf,
        'all_txt'       => $txt,
        'issues'        => [],
        'lookups'       => 0,
        'lookups_capped'=> false,
        'includes'      => [],
        'mechanisms'    => [],
        'all_qualifier' => null,
        'redirect_chain'=> [],
        'effective_record' => null,
        'effective_domain' => null,
        'has_redirect'  => false,
        'status'        => 'unknown',
    ];

    if (!$first['ok']) {
        $res['issues'][] = dns_fail_issue($domain, $first);
        return $res; // status stays 'unknown'
    }
    if (count($spf) > 1) {
        $res['issues'][] = ['level'=>'critical','msg'=>t('spf_multiple')];
    }
    if (count($spf) === 0) {
        $res['issues'][] = ['level'=>'critical','msg'=>t('spf_none')];
        $res['status'] = 'critical';
        return $res;
    }

    $localMechs     = []; // mechanisms of the LOCAL record (queried domain)
    $effectiveMechs = []; // mechanisms of the EFFECTIVE record (after redirects)
    $effectiveAll   = null;
    $effectiveRec   = $spf[0];
    $effectiveDom   = $domain;
    $currentRec     = $spf[0];
    $currentDom     = $domain;
    $chain          = [];
    $visited        = [strtolower($domain) => true];
    $hasRedirect    = false;
    $maxDepth       = 5;

    for ($depth = 0; $depth <= $maxDepth; $depth++) {
        $tokens = preg_split('/\s+/', trim($currentRec)) ?: [];
        array_shift($tokens); // v=spf1

        $localAll      = null;
        $localRedirect = null;
        $currentRecMechs = [];

        foreach ($tokens as $t) {
            if ($t === '') continue;
            $currentRecMechs[] = $t;
            $bare  = ltrim($t, '+-~?');
            $lower = strtolower($bare);

            if ($lower === 'all') {
                $localAll = ($t[0] === '+' || $t[0] === '-' || $t[0] === '~' || $t[0] === '?') ? $t[0] : '+';
            }
            if (preg_match('/^redirect=(.+)$/i', $bare, $m)) {
                $localRedirect = rtrim(strtolower($m[1]), '.');
            }
        }

        if ($depth === 0) $localMechs = $currentRecMechs;
        $effectiveMechs = $currentRecMechs;

        // "all" found: this is the effective record
        if ($localAll !== null) {
            $effectiveAll = $localAll;
            $effectiveRec = $currentRec;
            $effectiveDom = $currentDom;
            break;
        }

        // no "all" and no redirect: the record ends without a policy
        if ($localRedirect === null) {
            $effectiveRec = $currentRec;
            $effectiveDom = $currentDom;
            break;
        }

        // follow the redirect
        $hasRedirect = true;
        if (isset($visited[$localRedirect])) {
            $res['issues'][] = ['level'=>'critical','msg'=>t('spf_loop', $localRedirect)];
            break;
        }
        if ($depth === $maxDepth) {
            $res['issues'][] = ['level'=>'critical','msg'=>t('spf_too_deep', $maxDepth)];
            break;
        }
        $visited[$localRedirect] = true;

        if (!is_valid_dns_name($localRedirect)) {
            $res['issues'][] = ['level'=>'info','msg'=>t('spf_include_macro', $localRedirect)];
            break;
        }
        $next = spf_records($resolver, $localRedirect);
        if (!$next['ok']) {
            $res['issues'][] = dns_fail_issue($localRedirect, $next);
            break;
        }
        $nextSpf = $next['spf'];

        $chain[] = [
            'from'    => $currentDom,
            'to'      => $localRedirect,
            'record'  => $nextSpf[0] ?? null,
            'found'   => count($nextSpf) > 0,
            'multiple'=> count($nextSpf) > 1,
        ];

        if (count($nextSpf) === 0) {
            $res['issues'][] = ['level'=>'critical','msg'=>t('spf_redirect_no_spf', $localRedirect)];
            break;
        }
        if (count($nextSpf) > 1) {
            $res['issues'][] = ['level'=>'critical','msg'=>t('spf_redirect_multi', $localRedirect)];
        }

        $currentDom   = $localRedirect;
        $currentRec   = $nextSpf[0];
        $effectiveRec = $currentRec;
        $effectiveDom = $currentDom;
    }

    // DNS lookup count over the whole evaluation tree (nested includes and redirects)
    $ctx = ['notes' => [], 'queries' => 0, 'capped' => false, 'includes' => []];
    $totalLookups = spf_count_lookups($resolver, $spf[0], [strtolower($domain) => true], 0, $ctx);
    foreach ($ctx['notes'] as $n) $res['issues'][] = $n;

    $res['lookups']             = $totalLookups;
    $res['lookups_capped']      = $ctx['capped'];
    $res['includes']            = array_keys($ctx['includes']);
    $res['mechanisms']          = $localMechs;
    $res['effective_mechanisms']= $hasRedirect ? $effectiveMechs : null;
    $res['mechanisms_count']    = count($effectiveMechs);
    $res['all_qualifier']       = $effectiveAll;
    $res['redirect_chain']      = $chain;
    $res['has_redirect']        = $hasRedirect;
    $res['effective_record']    = $hasRedirect ? $effectiveRec : null;
    $res['effective_domain']    = $hasRedirect ? $effectiveDom : null;

    if ($ctx['capped']) {
        $res['issues'][] = ['level'=>'warning','msg'=>t('spf_lookups_capped')];
    }
    if ($totalLookups > 10) {
        $res['issues'][] = ['level'=>'critical','msg'=>t('spf_lookups_over', $totalLookups)];
    } elseif ($totalLookups >= 8) {
        $res['issues'][] = ['level'=>'warning','msg'=>t('spf_lookups_near', $totalLookups)];
    }

    if ($effectiveAll === '+') {
        $res['issues'][] = ['level'=>'critical','msg'=>t('spf_plus_all')];
    } elseif ($effectiveAll === '?') {
        $res['issues'][] = ['level'=>'warning','msg'=>t('spf_neutral_all')];
    } elseif ($effectiveAll === null) {
        $res['issues'][] = ['level'=>'warning','msg'=>t($hasRedirect ? 'spf_no_all_redirect' : 'spf_no_all')];
    } elseif ($hasRedirect) {
        $res['issues'][] = ['level'=>'info','msg'=>t('spf_via_redirect', $effectiveDom)];
    }

    $res['status'] = worst_status($res['issues']);
    return $res;
}

// ---------- DMARC ----------
// A single TXT query with the full answer section tells a valid delegation
// (`_dmarc CNAME -> TXT at the target`) from a real RFC 1034 conflict
// (CNAME + TXT on the same owner).
function analyze_dmarc(string $resolver, string $domain): array {
    $name   = '_dmarc.'.$domain;
    $nameLc = strtolower($name);

    $res = [
        'name'       => $name,
        'cname'      => [],
        'txt_all'    => [],
        'records'    => [],
        'managed_by' => null,
        'tags'       => [],
        'issues'     => [],
        'status'     => 'unknown',
    ];

    $q = dig_query($resolver, 'TXT', $name);
    if (!$q['ok']) {
        $res['issues'][] = dns_fail_issue($name, $q);
        return $res; // status stays 'unknown'
    }

    $cnameTarget = null;   // target of the CNAME on $name (if any)
    $txtDirect   = [];     // TXT owned by $name (potential RFC 1034 conflict)
    $txtResolved = [];     // TXT reached through the CNAME chain
    $rawTxtAll   = [];

    foreach ($q['records'] as $rec) {
        if ($rec['type'] === 'CNAME' && $rec['owner'] === $nameLc) {
            $cnameTarget = rtrim(strtolower($rec['rdata']), '.');
        } elseif ($rec['type'] === 'TXT') {
            $val = txt_value($rec['rdata']);
            $rawTxtAll[] = $val;
            if ($rec['owner'] === $nameLc) $txtDirect[] = $val;
            else                           $txtResolved[] = $val;
        }
    }

    $hasCname      = $cnameTarget !== null;
    $isDmarc       = function ($r) { return stripos($r, 'v=DMARC1') === 0; };
    $dmarcDirect   = array_values(array_filter($txtDirect,   $isDmarc));
    $dmarcResolved = array_values(array_filter($txtResolved, $isDmarc));

    $res['cname']   = $hasCname ? [$cnameTarget] : [];
    $res['txt_all'] = $rawTxtAll;

    if ($hasCname && count($dmarcDirect) > 0) {
        // REAL RFC 1034 conflict: CNAME and TXT on the same owner
        $res['managed_by']        = 'both';
        $res['cname_target']      = $cnameTarget;
        $res['cname_resolved_txt']= $txtResolved;
        $res['records']           = array_merge($dmarcDirect, $dmarcResolved);
        $res['issues'][]          = ['level'=>'critical','msg'=>t('dmarc_conflict')];
        $dmarc = $res['records'];
    } elseif ($hasCname) {
        // CNAME -> TXT at the target: VALID configuration (delegated DMARC)
        $res['managed_by']         = 'cname';
        $res['cname_target']       = $cnameTarget;
        $res['cname_resolved_txt'] = $txtResolved;
        $res['records']            = $dmarcResolved;
        if (!$dmarcResolved) {
            $res['issues'][] = ['level'=>'critical','msg'=>t('dmarc_cname_no_record', $cnameTarget)];
        }
        $dmarc = $dmarcResolved;
    } elseif ($dmarcDirect) {
        $res['managed_by'] = 'txt';
        $res['records']    = $dmarcDirect;
        $dmarc             = $dmarcDirect;
    } else {
        $res['issues'][] = ['level'=>'critical','msg'=>t('dmarc_none')];
        $res['status']   = 'critical';
        return $res;
    }

    if (count($dmarc) > 1) {
        $res['issues'][] = ['level'=>'critical','msg'=>t('dmarc_multiple')];
    }

    if (count($dmarc) >= 1) {
        $tags = [];
        foreach (explode(';', $dmarc[0]) as $part) {
            $part = trim($part);
            if ($part === '' || strpos($part, '=') === false) continue;
            [$k,$v] = array_map('trim', explode('=', $part, 2));
            $tags[strtolower($k)] = $v;
        }
        $res['tags'] = $tags;

        $p     = strtolower($tags['p']  ?? '');
        $sp    = strtolower($tags['sp'] ?? '');
        $pct   = isset($tags['pct']) ? (int)$tags['pct'] : 100;
        $rua   = $tags['rua'] ?? '';
        $adkim = strtolower($tags['adkim'] ?? 'r');
        $aspf  = strtolower($tags['aspf']  ?? 'r');

        if (!in_array($p, ['none','quarantine','reject'], true)) {
            $res['issues'][] = ['level'=>'critical','msg'=>t('dmarc_p_invalid')];
        } elseif ($p === 'none') {
            $res['issues'][] = ['level'=>'warning','msg'=>t('dmarc_p_none')];
        } elseif ($p === 'quarantine') {
            $res['issues'][] = ['level'=>'info','msg'=>t('dmarc_p_quarantine')];
        }
        if ($pct < 100) {
            $res['issues'][] = ['level'=>'warning','msg'=>t('dmarc_pct', $pct, $pct)];
        }
        if ($rua === '') {
            $res['issues'][] = ['level'=>'warning','msg'=>t('dmarc_no_rua')];
        }
        if ($sp === '' && $p === 'reject') {
            $res['issues'][] = ['level'=>'info','msg'=>t('dmarc_sp_inherit')];
        }
        if ($adkim === 's' || $aspf === 's') {
            $res['issues'][] = ['level'=>'info','msg'=>t('dmarc_strict')];
        }
    }

    $res['status'] = worst_status($res['issues']);
    return $res;
}

// ---------- DKIM ----------
/**
 * Parses a TXT value as a DKIM key record. Returns the tag map, or null when
 * the text is not a DKIM record (a p= tag is mandatory; v=, when present,
 * must be DKIM1). This keeps SPF/DMARC/verification strings published by a
 * wildcard from being reported as keys.
 */
function parse_dkim_record(string $txt): ?array {
    $tags = [];
    foreach (explode(';', $txt) as $part) {
        $part = trim($part);
        if ($part === '' || strpos($part, '=') === false) continue;
        [$k, $v] = array_map('trim', explode('=', $part, 2));
        $tags[strtolower($k)] = $v;
    }
    if (!array_key_exists('p', $tags)) return null;
    if (isset($tags['v']) && strcasecmp($tags['v'], 'DKIM1') !== 0) return null;
    $tags['p'] = (string)preg_replace('/\s+/', '', $tags['p']);
    return $tags;
}

/** Real size in bits of an RSA public key (p= value), or null if it cannot be read. */
function dkim_rsa_bits(string $p): ?int {
    if (!function_exists('openssl_pkey_get_public')) return null;
    $pem = "-----BEGIN PUBLIC KEY-----\n".chunk_split($p, 64, "\n")."-----END PUBLIC KEY-----\n";
    $key = @openssl_pkey_get_public($pem);
    if ($key === false) return null;
    $det = openssl_pkey_get_details($key);
    return (is_array($det) && isset($det['bits'])) ? (int)$det['bits'] : null;
}

/** One selector lookup: CNAME on the name itself + TXT values (direct or via CNAME). */
function dkim_lookup(string $resolver, string $name): array {
    $q = dig_query($resolver, 'TXT', $name);
    $nameLc = strtolower($name);
    $cname = [];
    $txt = [];
    foreach ($q['records'] as $r) {
        if ($r['type'] === 'CNAME' && $r['owner'] === $nameLc) $cname[] = $r['rdata'];
        elseif ($r['type'] === 'TXT') $txt[] = txt_value($r['rdata']);
    }
    return ['ok' => $q['ok'], 'cname' => $cname, 'txt' => $txt];
}

/**
 * @param list<array{s:string,d:string}> $targets  selector/domain pairs to query
 * @param array<string,bool> $usedByEml  "selector|domain" (lowercase) of the signatures of the uploaded message
 */
function analyze_dkim(string $resolver, array $targets, array $usedByEml): array {
    $found = [];
    $issues = [];
    $errors = 0;
    $done = 0;
    $wildcard = []; // domain => fingerprint of the wildcard answer, or null

    foreach ($targets as $tg) {
        $s = $tg['s'];
        $d = $tg['d'];
        if (budget_left() <= 0) break;
        $done++;

        // Wildcard probe (once per domain): a random selector that cannot exist.
        // If it answers, identical answers for real selectors are not keys.
        if (!array_key_exists($d, $wildcard)) {
            $wildcard[$d] = null;
            $probe = dkim_lookup($resolver, 'zz-probe-'.bin2hex(random_bytes(5)).'._domainkey.'.$d);
            if ($probe['ok'] && ($probe['cname'] || $probe['txt'])) {
                // CNAME targets of a wildcard are identical for every name, TXT too
                $wildcard[$d] = json_encode([$probe['cname'], $probe['txt']]);
                $issues[] = ['level' => 'info', 'msg' => t('dkim_wildcard', $d)];
            }
        }

        $name = $s.'._domainkey.'.$d;
        $lk = dkim_lookup($resolver, $name);
        if (!$lk['ok']) { $errors++; continue; }
        if (!$lk['txt'] && !$lk['cname']) continue;
        if ($wildcard[$d] !== null && json_encode([$lk['cname'], $lk['txt']]) === $wildcard[$d]) continue;

        $tags = null;
        foreach ($lk['txt'] as $r) {
            $tags = parse_dkim_record($r);
            if ($tags !== null) break;
        }
        // TXT that is not a DKIM key and no CNAME delegation: not a selector
        if ($tags === null && !$lk['cname']) continue;

        $entry = [
            'selector' => $s,
            'domain'   => $d,
            'name'     => $name,
            'cname'    => $lk['cname'],
            'txt'      => $lk['txt'],
            'state'    => 'no_key',   // active | testing | revoked | no_key
            'issues'   => [],
        ];

        if ($tags !== null) {
            $entry['tags'] = $tags;
            $ktype = strtolower($tags['k'] ?? 'rsa');
            $entry['key_type'] = $ktype;

            if ($tags['p'] === '') {
                // RFC 6376 §3.6.1: an empty p= means the key has been revoked
                $entry['state'] = 'revoked';
                $used = isset($usedByEml[strtolower($s).'|'.$d]);
                $entry['issues'][] = $used
                    ? ['level'=>'critical','msg'=>t('dkim_revoked_used')]
                    : ['level'=>'info','msg'=>t('dkim_revoked')];
            } else {
                $entry['state'] = 'active';
                if (isset($tags['t']) && strpos($tags['t'], 'y') !== false) {
                    $entry['state'] = 'testing';
                    $entry['issues'][] = ['level'=>'warning','msg'=>t('dkim_testing')];
                }
                if (base64_decode($tags['p'], true) === false) {
                    $entry['issues'][] = ['level'=>'warning','msg'=>t('dkim_bad_key')];
                } elseif ($ktype === 'ed25519') {
                    // 32-byte key by design: the RSA size checks do not apply
                    $entry['key_bits'] = 256;
                } else {
                    $bits = dkim_rsa_bits($tags['p']);
                    if ($bits !== null) {
                        $entry['key_bits'] = $bits;
                        if ($bits < 1024)     $entry['issues'][] = ['level'=>'warning','msg'=>t('dkim_weak', $bits)];
                        elseif ($bits < 2048) $entry['issues'][] = ['level'=>'info','msg'=>t('dkim_1024', $bits)];
                    } else {
                        // openssl not available: estimate from the base64 length
                        $blen = strlen($tags['p']);
                        if ($blen < 200)     $entry['issues'][] = ['level'=>'warning','msg'=>t('dkim_weak_len', $blen)];
                        elseif ($blen < 380) $entry['issues'][] = ['level'=>'info','msg'=>t('dkim_1024_len')];
                    }
                }
            }
        } else {
            // CNAME without a key at the target (e.g. inactive Microsoft 365 selector)
            $entry['issues'][] = ['level'=>'info','msg'=>t('dkim_cname_no_key')];
        }
        $found[] = $entry;
    }

    $skipped = count($targets) - $done;
    if ($skipped > 0) $issues[] = ['level'=>'warning','msg'=>t('dkim_truncated', $skipped)];
    if ($errors > 0)  $issues[] = ['level'=>'warning','msg'=>t('dkim_dns_errors', $errors)];

    $active = 0; $revoked = 0;
    $all = $issues;
    foreach ($found as $f) {
        if ($f['state'] === 'active' || $f['state'] === 'testing') $active++;
        if ($f['state'] === 'revoked') $revoked++;
        foreach ($f['issues'] as $i) $all[] = $i;
    }
    if (count($found) > 0 && $active === 0) {
        $issues[] = $all[] = ['level'=>'warning','msg'=>t('dkim_no_active')];
    }

    // critical: a revoked key is still used to sign; warning: nothing found,
    // no active key, weak/testing keys or incomplete scan; unknown: no answer at all
    $status = worst_status($all);
    if (count($found) === 0 && $status === 'ok') $status = 'warning';
    if ($done > 0 && $errors === $done)          $status = 'unknown';

    return [
        'tried'         => count($targets),
        'found'         => $found,
        'count'         => count($found),
        'active_count'  => $active,
        'revoked_count' => $revoked,
        'errors'        => $errors,
        'truncated'     => $skipped > 0,
        'issues'        => $issues,
        'status'        => $status,
    ];
}

// ---------- MX ----------
function analyze_mx(string $resolver, string $domain): array {
    $q = dig_query($resolver, 'MX', $domain);
    if (!$q['ok']) {
        return ['records' => [], 'issues' => [dns_fail_issue($domain, $q)], 'status' => 'unknown'];
    }
    $mx = [];
    foreach ($q['records'] as $r) {
        if ($r['type'] === 'MX' && preg_match('/^(\d+)\s+(.+?)\.?$/', $r['rdata'], $m)) {
            $mx[] = ['priority'=>(int)$m[1], 'host'=>$m[2]];
        }
    }
    usort($mx, function ($a, $b) { return $a['priority'] <=> $b['priority']; });

    $issues = [];
    if (count($mx) === 0) {
        $issues[] = ['level'=>'critical','msg'=>t('mx_none')];
    } elseif (count($mx) === 1) {
        $issues[] = ['level'=>'info','msg'=>t('mx_single')];
    }
    return [
        'records' => $mx,
        'issues'  => $issues,
        'status'  => count($mx) === 0 ? 'critical' : 'ok',
    ];
}

// ---------- EML ----------
/**
 * Extracts the signatures of an EML.
 * - Only DKIM-Signature is a DKIM signature of the sender: the key lives at
 *   <s>._domainkey.<d>, so s= is always read together with its own d=.
 * - ARC-Message-Signature / ARC-Seal are added by intermediate servers
 *   (gateways, anti-spam filters): selector and domain are NOT the sender's,
 *   they are only reported as information and never queried.
 *
 * @return array{dkim: list<array{s:string,d:string}>, arc: list<array{s:string,d:string}>}
 */
function extract_signatures_from_eml(string $content): array {
    $out = ['dkim' => [], 'arc' => []];
    // header block only (up to the first empty line), with RFC 5322 unfolding
    $parts   = preg_split('/\r?\n\r?\n/', $content, 2);
    $headers = (string)preg_replace('/\r?\n[ \t]+/', ' ', $parts[0] ?? '');
    if (!preg_match_all('/^(DKIM-Signature|ARC-Message-Signature):(.*)$/mi', $headers, $m, PREG_SET_ORDER)) {
        return $out;
    }
    $seen = [];
    foreach ($m as $h) {
        $kind = strcasecmp($h[1], 'DKIM-Signature') === 0 ? 'dkim' : 'arc';
        $tags = [];
        foreach (explode(';', $h[2]) as $kv) {
            $kv = trim($kv);
            if ($kv === '' || strpos($kv, '=') === false) continue;
            [$k, $v] = array_map('trim', explode('=', $kv, 2));
            $tags[strtolower($k)] = (string)preg_replace('/\s+/', '', $v);
        }
        $sel = $tags['s'] ?? '';
        $dom = strtolower(rtrim($tags['d'] ?? '', '.'));
        if (!is_valid_selector($sel) || !is_valid_domain($dom)) continue;
        $key = $kind.'|'.strtolower($sel).'|'.$dom;
        if (isset($seen[$key])) continue;
        $seen[$key] = true;
        $out[$kind][] = ['s' => $sel, 'd' => $dom];
    }
    return $out;
}

/**
 * DMARC identifier alignment between the DKIM d= domain and the From domain:
 *   exact   -> same domain (passes with adkim=s and adkim=r)
 *   relaxed -> one is a subdomain of the other (passes only with adkim=r)
 *   none    -> unrelated domains
 * Approximation without the Public Suffix List: two sibling subdomains of the
 * same organizational domain (a.example.com / b.example.com) are reported as
 * 'none' although relaxed alignment would accept them.
 */
function dkim_alignment(string $d, string $from): string {
    if ($d === $from) return 'exact';
    if (ends_with($from, '.'.$d) || ends_with($d, '.'.$from)) return 'relaxed';
    return 'none';
}

/**
 * Domains of the addresses in the From and To/Cc headers.
 * Used to tell whether the message is internal (same domain): Microsoft 365
 * and other providers do not DKIM-sign mail that stays inside the tenant.
 *
 * @return array{from: list<string>, rcpt: list<string>}
 */
function eml_address_domains(string $content): array {
    $parts   = preg_split('/\r?\n\r?\n/', $content, 2);
    $headers = (string)preg_replace('/\r?\n[ \t]+/', ' ', $parts[0] ?? '');
    $domainsOf = function (string $name) use ($headers): array {
        $out = [];
        if (preg_match_all('/^'.$name.':(.*)$/mi', $headers, $m)) {
            foreach ($m[1] as $line) {
                if (preg_match_all('/[A-Za-z0-9._%+\-]+@([A-Za-z0-9.\-]+\.[A-Za-z]{2,})/', $line, $am)) {
                    foreach ($am[1] as $d) {
                        $d = strtolower(rtrim($d, '.'));
                        if (is_valid_domain($d)) $out[] = $d;
                    }
                }
            }
        }
        return $out;
    };
    return [
        'from' => array_values(array_unique($domainsOf('From'))),
        'rcpt' => array_values(array_unique(array_merge($domainsOf('To'), $domainsOf('Cc')))),
    ];
}

/** Internal = a single sender domain and every To/Cc recipient in that same domain. */
function eml_is_internal(array $addr): bool {
    if (count($addr['from']) !== 1 || !$addr['rcpt']) return false;
    foreach ($addr['rcpt'] as $d) if ($d !== $addr['from'][0]) return false;
    return true;
}

// ---------- INPUT ----------
$LANG = pick_lang($_POST['lang'] ?? ($_GET['lang'] ?? null));

$method = $_SERVER['REQUEST_METHOD'] ?? 'GET';
if ($method !== 'POST') bail(405, t('err_only_post'));

$contentType = (string)($_SERVER['CONTENT_TYPE'] ?? '');
$domain     = '';
$selectors  = [];
$resolver   = DEFAULT_RESOLVER;
$emlContent = '';

/** Returns $v only when it is a string (JSON input can hold any type). */
$str = function ($v, string $default = ''): string {
    return is_string($v) ? trim($v) : $default;
};

if (stripos($contentType, 'application/json') !== false) {
    $raw  = file_get_contents('php://input') ?: '';
    $data = json_decode($raw, true);
    if (!is_array($data)) bail(400, t('err_bad_json'));
    $LANG     = pick_lang($data['lang'] ?? ($_GET['lang'] ?? null));
    $domain   = strtolower($str($data['domain'] ?? ''));
    $resolver = $str($data['resolver'] ?? '', DEFAULT_RESOLVER) ?: DEFAULT_RESOLVER;
    if (isset($data['selectors']) && is_array($data['selectors'])) {
        foreach ($data['selectors'] as $s) if (is_string($s)) $selectors[] = trim($s);
    }
    if (isset($data['eml_b64']) && is_string($data['eml_b64']) && $data['eml_b64'] !== '') {
        // base64 grows the payload by 4/3
        if (strlen($data['eml_b64']) > (int)ceil(MAX_EML_BYTES * 4 / 3) + 4) bail(413, t('err_eml_big'));
        $emlContent = base64_decode($data['eml_b64'], true) ?: '';
    }
} else {
    // A body larger than post_max_size reaches PHP with empty $_POST/$_FILES
    if (!$_POST && !$_FILES && (int)($_SERVER['CONTENT_LENGTH'] ?? 0) > 0) bail(413, t('err_post_big'));
    $domain   = strtolower($str($_POST['domain'] ?? ''));
    $resolver = $str($_POST['resolver'] ?? '', DEFAULT_RESOLVER) ?: DEFAULT_RESOLVER;
    $selRaw   = $str($_POST['selectors'] ?? '');
    if ($selRaw !== '') {
        $selectors = array_values(array_filter(array_map('trim', preg_split('/[\s,]+/', $selRaw) ?: [])));
    }
    if (isset($_FILES['eml']) && is_array($_FILES['eml']) && !is_array($_FILES['eml']['error'] ?? null)) {
        $err = (int)($_FILES['eml']['error'] ?? UPLOAD_ERR_NO_FILE);
        if ($err === UPLOAD_ERR_INI_SIZE || $err === UPLOAD_ERR_FORM_SIZE) bail(413, t('err_upload', $err));
        if ($err !== UPLOAD_ERR_OK && $err !== UPLOAD_ERR_NO_FILE)          bail(400, t('err_upload', $err));
        if ($err === UPLOAD_ERR_OK && is_uploaded_file((string)$_FILES['eml']['tmp_name'])) {
            if ((int)($_FILES['eml']['size'] ?? 0) > MAX_EML_BYTES) bail(413, t('err_eml_big'));
            $emlContent = file_get_contents((string)$_FILES['eml']['tmp_name']) ?: '';
        }
    }
}

if ($domain === '' || !is_valid_domain($domain)) bail(400, t('err_domain'));
if (!is_valid_resolver($resolver))               bail(400, t('err_resolver'));

// ---------- DoS GUARDS ----------
// Per-IP limit first (so one client cannot fill every global slot), then the
// global one. Busy -> HTTP 429 + Retry-After: the web UI waits and retries by
// itself (client-side queue), so no PHP worker is held while waiting.
$bucket  = client_bucket();
$IP_SLOT = $bucket === null ? true : acquire_slot('ip'.$bucket, MAX_PER_IP);
if ($IP_SLOT === null) {
    header('Retry-After: '.RETRY_AFTER);
    bail(429, t('err_busy_ip'), ['retry_after' => RETRY_AFTER, 'scope' => 'ip']);
}
$SLOT = acquire_slot('slot', MAX_CONCURRENT);
if ($SLOT === null) {
    header('Retry-After: '.RETRY_AFTER);
    bail(429, t('err_busy'), ['retry_after' => RETRY_AFTER, 'scope' => 'global']);
}

// Probe: one cheap query tells right away whether dig works and whether the
// resolver answers, instead of burning the whole time budget on timeouts.
$T_START = microtime(true);
$probe = dig_query($resolver, 'SOA', $domain);
if (!$probe['ok']) {
    if ($probe['error'] === 'exec')    bail(500, t('err_dig'));
    if ($probe['error'] === 'timeout') bail(502, t('err_resolver_down', $resolver));
    bail(502, t('err_resolver_status', $resolver, $probe['error']));
}
$DNS_ERRORS = [];

// ---------- EML ----------
$emlTargets = [];   // signatures aligned with the analysed domain: their keys are looked up
$usedByEml  = [];
$emlInfo    = null;
if ($emlContent !== '') {
    $sigs = extract_signatures_from_eml($emlContent);
    $dkimSigs = [];
    foreach ($sigs['dkim'] as $sg) {
        $sg['alignment'] = dkim_alignment($sg['d'], $domain);
        $dkimSigs[] = $sg;
        if ($sg['alignment'] !== 'none') {
            $emlTargets[] = ['s' => $sg['s'], 'd' => $sg['d']];
            $usedByEml[strtolower($sg['s']).'|'.$sg['d']] = true;
        }
    }
    $addr = eml_address_domains($emlContent);
    $emlInfo = [
        'dkim_signed'     => count($dkimSigs) > 0,
        'internal'        => eml_is_internal($addr), // sender and recipients in the same domain
        'from_domains'    => $addr['from'],
        'rcpt_domains'    => $addr['rcpt'],
        'dkim_signatures' => $dkimSigs,       // every DKIM-Signature, with its alignment
        'arc_signatures'  => $sigs['arc'],    // ignored for DKIM verification
    ];
}

// Selectors: custom ones and those of the EML signatures are MERGED (so the
// key that actually signed the message is always checked); the default list
// is used only when neither is available.
$selectors = array_values(array_filter($selectors, 'is_valid_selector'));
$targets = [];
$seenT = [];
$addTarget = function (string $s, string $d) use (&$targets, &$seenT): void {
    $k = strtolower($s).'|'.$d;
    if (isset($seenT[$k])) return;
    $seenT[$k] = true;
    $targets[] = ['s' => $s, 'd' => $d];
};
foreach ($emlTargets as $tg) $addTarget($tg['s'], $tg['d']);
foreach ($selectors as $s)   $addTarget($s, $domain);
if (!$targets) {
    foreach (DEFAULT_SELECTORS as $s) $addTarget($s, $domain);
}
if (count($targets) > MAX_SELECTORS) $targets = array_slice($targets, 0, MAX_SELECTORS);

// ---------- RUN ----------
$t0 = microtime(true);
$out = [
    'domain'                  => $domain,
    'resolver'                => $resolver,
    'lang'                    => $LANG,
    'timestamp'               => gmdate('c'),
    'eml_selectors_extracted' => array_values(array_unique(array_column($emlTargets, 's'))),
    'eml'                     => $emlInfo,
    'selectors_used'          => array_values(array_unique(array_column($targets, 's'))),
    'mx'    => analyze_mx($resolver, $domain),
    'spf'   => analyze_spf($resolver, $domain),
    'dmarc' => analyze_dmarc($resolver, $domain),
    'dkim'  => analyze_dkim($resolver, $targets, $usedByEml),
];
$out['dns_errors'] = count($DNS_ERRORS);
$out['elapsed_ms'] = (int)round((microtime(true)-$t0)*1000);

// overall: critical > warning > unknown > ok
$rank = ['ok' => 0, 'unknown' => 1, 'warning' => 2, 'critical' => 3];
$worst = 'ok';
foreach (['mx','spf','dmarc','dkim'] as $k) {
    $s = $out[$k]['status'] ?? 'ok';
    if (($rank[$s] ?? 0) > $rank[$worst]) $worst = $s;
}
$out['overall_status'] = $worst;

echo json_encode($out, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT);
