<?php
/**
 * maildns-check API
 * Endpoint unico: POST JSON { domain, selectors?, resolver?, eml? (base64) }
 * oppure multipart con file 'eml'
 */

declare(strict_types=1);

header('Content-Type: application/json; charset=utf-8');
header('X-Content-Type-Options: nosniff');

// ---------- CONFIG ----------
const DEFAULT_RESOLVER = '1.1.1.1';
const DIG_TIMEOUT      = 3;
const DIG_TRIES        = 2;

// Selettori DKIM "noti" per provider, usati se l'utente non ne specifica.
const DEFAULT_SELECTORS = [
    // generici
    'default','mail','dkim','email','key1','smtp','dk',
    // Microsoft 365 / Exchange
    'selector1','selector2',
    // Google Workspace
    'google',
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
    // Brevo / Sendinblue
    'mail1','mail2',
    // SendPulse
    'sendpulse',
    // Klaviyo / ActiveCampaign / ConvertKit / Drip
    'dkim2','ck1','drip',
    // Zendesk
    'zendesk1','zendesk2',
    // AWeber
    'aweber_key_a','aweber_key_b','aweber_key_c',
    // Cisco
    'cisco1','cisco2',
    // legacy
    's2048','s1024',
    // date-based (rotazione)
    '20230601','20240101','20240601','20250101','20250601','20260101',
];

// ---------- UTILS ----------
function bail(int $code, string $msg): void {
    http_response_code($code);
    echo json_encode(['error' => $msg], JSON_UNESCAPED_SLASHES);
    exit;
}

function is_valid_domain(string $d): bool {
    if (strlen($d) > 253) return false;
    return (bool)preg_match('/^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/i', $d);
}

function is_valid_selector(string $s): bool {
    return (bool)preg_match('/^[a-zA-Z0-9_\-\.]{1,63}$/', $s);
}

function is_valid_resolver(string $r): bool {
    return (bool)filter_var($r, FILTER_VALIDATE_IP);
}

/**
 * dig sicuro: argomenti passati come array a proc_open, niente shell injection.
 */
function dig(string $resolver, string $type, string $name): array {
    $cmd = [
        'dig', '@'.$resolver, '+short', '+time='.DIG_TIMEOUT, '+tries='.DIG_TRIES,
        $type, $name,
    ];
    $desc = [1 => ['pipe','w'], 2 => ['pipe','w']];
    $proc = @proc_open($cmd, $desc, $pipes);
    if (!is_resource($proc)) return [];
    $out = stream_get_contents($pipes[1]);
    fclose($pipes[1]); fclose($pipes[2]);
    proc_close($proc);
    $lines = array_values(array_filter(array_map('trim', explode("\n", (string)$out)), fn($x) => $x !== ''));
    return $lines;
}

/**
 * dig con answer section completa: restituisce righe parsate
 *   [['owner'=>..., 'type'=>..., 'rdata'=>...], ...]
 * Serve per distinguere record diretti da record risolti via CNAME chain
 * (cosa impossibile da fare con `dig +short`, che segue silenziosamente i CNAME).
 */
function dig_answer(string $resolver, string $type, string $name): array {
    $cmd = [
        'dig', '@'.$resolver, '+noall', '+answer',
        '+time='.DIG_TIMEOUT, '+tries='.DIG_TRIES,
        $type, $name,
    ];
    $desc = [1 => ['pipe','w'], 2 => ['pipe','w']];
    $proc = @proc_open($cmd, $desc, $pipes);
    if (!is_resource($proc)) return [];
    $out = stream_get_contents($pipes[1]);
    fclose($pipes[1]); fclose($pipes[2]);
    proc_close($proc);

    $records = [];
    foreach (explode("\n", (string)$out) as $line) {
        $line = trim($line);
        if ($line === '' || $line[0] === ';') continue;
        // formato: owner TTL CLASS TYPE rdata...
        if (preg_match('/^(\S+)\s+\d+\s+IN\s+(\S+)\s+(.+)$/i', $line, $m)) {
            $records[] = [
                'owner' => rtrim(strtolower($m[1]), '.'),
                'type'  => strtoupper($m[2]),
                'rdata' => trim($m[3]),
            ];
        }
    }
    return $records;
}

/**
 * dig TXT restituisce stringhe con doppi apici e segmentate ("foo" "bar"): normalizza.
 */
function normalize_txt(array $lines): array {
    $out = [];
    foreach ($lines as $l) {
        if (preg_match_all('/"((?:[^"\\\\]|\\\\.)*)"/', $l, $m)) {
            $out[] = implode('', $m[1]);
        } else {
            $out[] = $l;
        }
    }
    return $out;
}

// ---------- ANALISI SPF ----------
// Segue il modificatore redirect= ricorsivamente (RFC 7208 §6.1):
// redirect delega INTEGRALMENTE la politica al dominio target.
// Con redirect, il meccanismo "all" nel record locale è inutile e per
// convenzione si omette; l'"all" effettivo è quello del target finale.
function analyze_spf(string $resolver, string $domain): array {
    $txt = normalize_txt(dig($resolver, 'TXT', $domain));
    $spf = [];
    foreach ($txt as $r) if (stripos($r, 'v=spf1') === 0) $spf[] = $r;

    $res = [
        'found'         => count($spf) > 0,
        'records'       => $spf,
        'all_txt'       => $txt,
        'issues'        => [],
        'lookups'       => 0,
        'mechanisms'    => [],
        'all_qualifier' => null,
        'redirect_chain'=> [],
        'effective_record' => null,
        'effective_domain' => null,
        'has_redirect'  => false,
        'status'        => 'unknown',
    ];

    if (count($spf) > 1) {
        $res['issues'][] = ['level'=>'critical','msg'=>'Più di un record SPF (v=spf1) presente. RFC 7208 vieta record multipli, gli MTA li considereranno PermError.'];
    }
    if (count($spf) === 0) {
        $res['issues'][] = ['level'=>'critical','msg'=>'Nessun record SPF trovato per il dominio.'];
        $res['status'] = 'critical';
        return $res;
    }

    $totalLookups   = 0;
    $localMechs     = []; // meccanismi del record LOCALE (dominio interrogato)
    $effectiveMechs = []; // meccanismi del record EFFETTIVO (dopo eventuale redirect)
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
        $tokens = preg_split('/\s+/', trim($currentRec));
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
                $localRedirect = strtolower($m[1]);
            }
            // meccanismi che contano per il limite dei 10 DNS lookup (RFC 7208 §4.6.4)
            if (preg_match('/^(include|a|mx|ptr|exists|redirect)([:=].*)?$/i', $lower)) {
                $totalLookups++;
            }
        }

        // se siamo al primo giro, questi sono i meccanismi del record LOCALE
        if ($depth === 0) {
            $localMechs = $currentRecMechs;
        }
        // i meccanismi del record corrente sono quelli "effettivi" finché non andiamo oltre
        $effectiveMechs = $currentRecMechs;

        if (strlen($currentRec) > 255) {
            $res['issues'][] = ['level'=>'info','msg'=>"Record SPF di $currentDom oltre 255 caratteri: assicurarsi che sia segmentato in più stringhe TXT."];
        }

        // se trovo all, mi fermo: questo è il record effettivo
        if ($localAll !== null) {
            $effectiveAll = $localAll;
            $effectiveRec = $currentRec;
            $effectiveDom = $currentDom;
            break;
        }

        // niente all, niente redirect: record terminato senza policy
        if ($localRedirect === null) {
            $effectiveRec = $currentRec;
            $effectiveDom = $currentDom;
            break;
        }

        // segue redirect
        $hasRedirect = true;
        if (isset($visited[$localRedirect])) {
            $res['issues'][] = ['level'=>'critical','msg'=>"Loop nella catena di redirect SPF: $localRedirect già visitato."];
            break;
        }
        if ($depth === $maxDepth) {
            $res['issues'][] = ['level'=>'critical','msg'=>"Catena di redirect SPF troppo profonda (oltre $maxDepth livelli)."];
            break;
        }
        $visited[$localRedirect] = true;

        $nextTxt = normalize_txt(dig($resolver, 'TXT', $localRedirect));
        $nextSpf = [];
        foreach ($nextTxt as $r) if (stripos($r, 'v=spf1') === 0) $nextSpf[] = $r;

        $chain[] = [
            'from'    => $currentDom,
            'to'      => $localRedirect,
            'record'  => $nextSpf[0] ?? null,
            'found'   => count($nextSpf) > 0,
            'multiple'=> count($nextSpf) > 1,
        ];

        if (count($nextSpf) === 0) {
            $res['issues'][] = ['level'=>'critical','msg'=>"Redirect SPF a $localRedirect ma il target non ha record v=spf1 (PermError)."];
            break;
        }
        if (count($nextSpf) > 1) {
            $res['issues'][] = ['level'=>'critical','msg'=>"Il target redirect $localRedirect ha più record v=spf1 (PermError)."];
        }

        $currentDom   = $localRedirect;
        $currentRec   = $nextSpf[0];
        $effectiveRec = $currentRec;
        $effectiveDom = $currentDom;
    }

    $res['lookups']             = $totalLookups;
    $res['mechanisms']          = $localMechs;                              // solo locale, breve
    $res['effective_mechanisms']= $hasRedirect ? $effectiveMechs : null;    // dopo redirect, solo se diverso
    $res['mechanisms_count']    = count($effectiveMechs);                   // conteggio per riferimento
    $res['all_qualifier']       = $effectiveAll;
    $res['redirect_chain']      = $chain;
    $res['has_redirect']        = $hasRedirect;
    $res['effective_record']    = $hasRedirect ? $effectiveRec : null;
    $res['effective_domain']    = $hasRedirect ? $effectiveDom : null;

    if ($totalLookups > 10) {
        $res['issues'][] = ['level'=>'critical','msg'=>"Superato il limite di 10 DNS lookup ($totalLookups). Risultato SPF sarà PermError."];
    } elseif ($totalLookups >= 8) {
        $res['issues'][] = ['level'=>'warning','msg'=>"Vicino al limite di 10 DNS lookup ($totalLookups/10). Considera flattening."];
    }

    if ($effectiveAll === '+') {
        $res['issues'][] = ['level'=>'critical','msg'=>'Qualificatore "+all" presente: chiunque può inviare email per il dominio. Configurazione INSICURA.'];
    } elseif ($effectiveAll === '?') {
        $res['issues'][] = ['level'=>'warning','msg'=>'Qualificatore "?all" (neutral): nessuna policy effettiva.'];
    } elseif ($effectiveAll === null) {
        if ($hasRedirect) {
            $res['issues'][] = ['level'=>'warning','msg'=>'Manca il meccanismo "all" anche nel record effettivo dopo il redirect: comportamento non definito sui mittenti non listati.'];
        } else {
            $res['issues'][] = ['level'=>'warning','msg'=>'Manca il meccanismo "all" finale: comportamento non definito sui mittenti non listati.'];
        }
    } elseif ($hasRedirect) {
        // info: il redirect funziona, all preso dal target
        $res['issues'][] = ['level'=>'info','msg'=>"Policy SPF risolta tramite redirect a $effectiveDom. Il meccanismo \"all\" non va aggiunto nel record locale, perché il redirect delega l'intera policy al target."];
    }

    $hasCrit = array_filter($res['issues'], fn($i)=>$i['level']==='critical');
    $hasWarn = array_filter($res['issues'], fn($i)=>$i['level']==='warning');
    $res['status'] = $hasCrit ? 'critical' : ($hasWarn ? 'warning' : 'ok');

    return $res;
}

// ---------- ANALISI DMARC ----------
// FIX: distinguere fra (a) configurazione corretta `_dmarc CNAME -> TXT del target`
// e (b) reale conflitto RFC 1034 con CNAME + TXT sullo stesso owner.
// `dig +short TXT` segue i CNAME silenziosamente, quindi non basta verificare
// "CNAME presente && TXT presente" come faceva la vecchia logica.
function analyze_dmarc(string $resolver, string $domain): array {
    $name   = '_dmarc.'.$domain;
    $nameLc = strtolower($name);

    // Una sola query TXT con answer section completa: contiene sia il CNAME
    // (se esiste sull'owner) sia il/i TXT finali della chain, ciascuno con
    // il proprio owner. È così possibile sapere se un TXT è "diretto"
    // sul nome richiesto o se proviene dal target di un CNAME.
    $answer = dig_answer($resolver, 'TXT', $name);

    $cnameTarget = null;   // target del CNAME su $name (se presente)
    $txtDirect   = [];     // TXT con owner == $name  (potenziale conflitto RFC 1034)
    $txtResolved = [];     // TXT raggiunti via CNAME chain
    $rawTxtAll   = [];     // tutti i TXT (per debug/UI)

    foreach ($answer as $rec) {
        if ($rec['type'] === 'CNAME' && $rec['owner'] === $nameLc) {
            $cnameTarget = rtrim(strtolower($rec['rdata']), '.');
        } elseif ($rec['type'] === 'TXT') {
            // estrai stringhe TXT dal formato "quoted" "string" (gestisce TXT segmentati)
            if (preg_match_all('/"((?:[^"\\\\]|\\\\.)*)"/', $rec['rdata'], $mm)) {
                $val = implode('', $mm[1]);
            } else {
                $val = $rec['rdata'];
            }
            $rawTxtAll[] = $val;
            if ($rec['owner'] === $nameLc) {
                $txtDirect[] = $val;
            } else {
                $txtResolved[] = $val;
            }
        }
    }

    $hasCname      = $cnameTarget !== null;
    $dmarcDirect   = array_values(array_filter($txtDirect,   fn($r) => stripos($r,'v=DMARC1') === 0));
    $dmarcResolved = array_values(array_filter($txtResolved, fn($r) => stripos($r,'v=DMARC1') === 0));

    $res = [
        'name'       => $name,
        'cname'      => $hasCname ? [$cnameTarget] : [],
        'txt_all'    => $rawTxtAll,
        'records'    => [],
        'managed_by' => null,
        'tags'       => [],
        'issues'     => [],
        'status'     => 'unknown',
    ];

    if ($hasCname && count($dmarcDirect) > 0) {
        // Conflitto REALE RFC 1034: CNAME e TXT entrambi sullo stesso owner.
        $res['managed_by']        = 'both';
        $res['cname_target']      = $cnameTarget;
        $res['cname_resolved_txt']= $txtResolved;
        $res['records']           = array_merge($dmarcDirect, $dmarcResolved);
        $res['issues'][]          = ['level'=>'critical','msg'=>'CONFLITTO: presenti SIA CNAME SIA TXT sulla stessa label _dmarc. RFC 1034 vieta CNAME coesistente con altri record sullo stesso owner. I resolver autoritativi rifiuteranno la zona o ignoreranno uno dei due. Configurazione da correggere SUBITO.'];
        $dmarc = $res['records'];
    } elseif ($hasCname) {
        // CNAME -> TXT del target: configurazione VALIDA (DMARC delegato).
        $res['managed_by']         = 'cname';
        $res['cname_target']       = $cnameTarget;
        $res['cname_resolved_txt'] = $txtResolved;
        $res['records']            = $dmarcResolved;
        if (!$dmarcResolved) {
            $res['issues'][] = ['level'=>'critical','msg'=>"Il CNAME punta a $cnameTarget ma non restituisce alcun record v=DMARC1 valido."];
        }
        $dmarc = $dmarcResolved;
    } elseif ($dmarcDirect) {
        $res['managed_by'] = 'txt';
        $res['records']    = $dmarcDirect;
        $dmarc             = $dmarcDirect;
    } else {
        $res['issues'][] = ['level'=>'critical','msg'=>'Nessun record DMARC trovato (né TXT né CNAME su _dmarc).'];
        $res['status']   = 'critical';
        return $res;
    }

    if (count($dmarc) > 1) {
        $res['issues'][] = ['level'=>'critical','msg'=>'Più record DMARC presenti. RFC 7489 prevede un solo record, gli MTA ignoreranno tutti.'];
    }

    if (count($dmarc) >= 1) {
        $tags = [];
        foreach (explode(';', $dmarc[0]) as $part) {
            $part = trim($part);
            if ($part === '') continue;
            if (strpos($part, '=') === false) continue;
            [$k,$v] = array_map('trim', explode('=', $part, 2));
            $tags[strtolower($k)] = $v;
        }
        $res['tags'] = $tags;

        $p     = strtolower($tags['p']  ?? '');
        $sp    = strtolower($tags['sp'] ?? '');
        $pct   = isset($tags['pct']) ? (int)$tags['pct'] : 100;
        $rua   = $tags['rua'] ?? '';
        $ruf   = $tags['ruf'] ?? '';
        $adkim = strtolower($tags['adkim'] ?? 'r');
        $aspf  = strtolower($tags['aspf']  ?? 'r');

        if (!in_array($p, ['none','quarantine','reject'], true)) {
            $res['issues'][] = ['level'=>'critical','msg'=>'Tag p= mancante o non valido (deve essere none|quarantine|reject).'];
        } elseif ($p === 'none') {
            $res['issues'][] = ['level'=>'warning','msg'=>'Policy p=none: solo monitoring, NON blocca le mail di phishing. Pianifica passaggio a quarantine/reject.'];
        } elseif ($p === 'quarantine') {
            $res['issues'][] = ['level'=>'info','msg'=>'Policy p=quarantine: protezione media. Per il massimo, considera p=reject.'];
        }
        if ($pct < 100) {
            $res['issues'][] = ['level'=>'warning','msg'=>"pct=$pct: la policy si applica solo al $pct% dei messaggi non allineati."];
        }
        if ($rua === '') {
            $res['issues'][] = ['level'=>'warning','msg'=>'Manca il tag rua=, non riceverai i report aggregati, impossibile monitorare.'];
        }
        if ($sp === '' && $p === 'reject') {
            $res['issues'][] = ['level'=>'info','msg'=>'sp= non specificato: i sottodomini ereditano da p=reject.'];
        }
        if ($adkim === 's' || $aspf === 's') {
            $res['issues'][] = ['level'=>'info','msg'=>'Allineamento strict (adkim/aspf=s) attivo, più severo del default relaxed.'];
        }
    }

    $hasCrit = array_filter($res['issues'], fn($i)=>$i['level']==='critical');
    $hasWarn = array_filter($res['issues'], fn($i)=>$i['level']==='warning');
    $res['status'] = $hasCrit ? 'critical' : ($hasWarn ? 'warning' : 'ok');

    return $res;
}

// ---------- DKIM ----------
function analyze_dkim(string $resolver, string $domain, array $selectors): array {
    $found = [];
    foreach ($selectors as $s) {
        if (!is_valid_selector($s)) continue;
        $name  = $s.'._domainkey.'.$domain;
        $txt   = normalize_txt(dig($resolver, 'TXT', $name));
        $cname = dig($resolver, 'CNAME', $name);
        if (!$txt && !$cname) continue;

        $entry = [
            'selector' => $s,
            'name'     => $name,
            'cname'    => $cname,
            'txt'      => $txt,
            'issues'   => [],
        ];

        $rec = '';
        foreach ($txt as $r) {
            if (stripos($r, 'v=DKIM1') !== false || stripos($r, 'p=') !== false) { $rec = $r; break; }
        }
        if ($rec) {
            $tags = [];
            foreach (explode(';', $rec) as $part) {
                $part = trim($part);
                if ($part === '' || strpos($part,'=') === false) continue;
                [$k,$v] = array_map('trim', explode('=', $part, 2));
                $tags[strtolower($k)] = $v;
            }
            $entry['tags'] = $tags;

            if (isset($tags['p']) && $tags['p'] === '') {
                $entry['issues'][] = ['level'=>'critical','msg'=>'p= vuoto, chiave revocata o disabilitata.'];
            }
            if (isset($tags['t']) && strpos($tags['t'], 'y') !== false) {
                $entry['issues'][] = ['level'=>'warning','msg'=>'Flag t=y: DKIM in modalità testing, i verifier devono ignorare i failure.'];
            }
            // stima dimensione chiave: p= base64 di SubjectPublicKeyInfo DER.
            if (isset($tags['p']) && $tags['p'] !== '') {
                $blen = strlen($tags['p']);
                if ($blen < 200) {
                    $entry['issues'][] = ['level'=>'warning','msg'=>"Chiave probabile inferiore a 1024 bit (b64 len $blen), deprecata."];
                } elseif ($blen < 380) {
                    $entry['issues'][] = ['level'=>'info','msg'=>"Chiave circa 1024 bit: funzionante ma 2048 raccomandato."];
                }
            }
        }
        $found[] = $entry;
    }
    return [
        'tried'  => count($selectors),
        'found'  => $found,
        'count'  => count($found),
        'status' => count($found) === 0 ? 'warning' : 'ok',
    ];
}

// ---------- MX ----------
function analyze_mx(string $resolver, string $domain): array {
    $raw = dig($resolver, 'MX', $domain);
    $mx = [];
    foreach ($raw as $r) {
        if (preg_match('/^(\d+)\s+(.+?)\.?$/', $r, $m)) {
            $mx[] = ['priority'=>(int)$m[1], 'host'=>$m[2]];
        }
    }
    usort($mx, fn($a,$b)=>$a['priority']<=>$b['priority']);

    $issues = [];
    if (count($mx) === 0) {
        $issues[] = ['level'=>'critical','msg'=>'Nessun record MX trovato: il dominio non può ricevere posta.'];
    } elseif (count($mx) === 1) {
        $issues[] = ['level'=>'info','msg'=>'Un solo MX: nessuna ridondanza in caso di failure del primario.'];
    }
    return [
        'records' => $mx,
        'issues'  => $issues,
        'status'  => count($mx) === 0 ? 'critical' : 'ok',
    ];
}

// ---------- ESTRAZIONE SELETTORI DA EML ----------
function extract_selectors_from_eml(string $content): array {
    $sels = [];
    $content = preg_replace('/\r?\n[ \t]+/', ' ', $content);
    if (preg_match_all('/^(?:DKIM-Signature|ARC-Message-Signature):.*$/mi', $content, $m)) {
        foreach ($m[0] as $line) {
            if (preg_match_all('/(?:^|[\s;])s=([^;\s]+)/i', $line, $sm)) {
                foreach ($sm[1] as $s) {
                    $s = trim($s);
                    if (is_valid_selector($s)) $sels[$s] = true;
                }
            }
        }
    }
    return array_keys($sels);
}

// ---------- INPUT ----------
$method = $_SERVER['REQUEST_METHOD'] ?? 'GET';
if ($method !== 'POST') bail(405, 'Only POST');

$contentType = $_SERVER['CONTENT_TYPE'] ?? '';
$domain     = '';
$selectors  = [];
$resolver   = DEFAULT_RESOLVER;
$emlContent = '';

if (stripos($contentType, 'application/json') !== false) {
    $raw  = file_get_contents('php://input') ?: '';
    $data = json_decode($raw, true);
    if (!is_array($data)) bail(400, 'JSON non valido');
    $domain   = strtolower(trim($data['domain']   ?? ''));
    $resolver = trim($data['resolver'] ?? DEFAULT_RESOLVER);
    if (isset($data['selectors']) && is_array($data['selectors'])) {
        $selectors = array_map('trim', $data['selectors']);
    }
    if (!empty($data['eml_b64'])) {
        $emlContent = base64_decode($data['eml_b64'], true) ?: '';
    }
} else {
    $domain   = strtolower(trim($_POST['domain']   ?? ''));
    $resolver = trim($_POST['resolver'] ?? DEFAULT_RESOLVER);
    if (!empty($_POST['selectors'])) {
        $selectors = array_filter(array_map('trim', preg_split('/[\s,]+/', $_POST['selectors'])));
    }
    if (!empty($_FILES['eml']['tmp_name']) && is_uploaded_file($_FILES['eml']['tmp_name'])) {
        if (($_FILES['eml']['size'] ?? 0) > 5_000_000) bail(413, 'File EML troppo grande (max 5 MB)');
        $emlContent = file_get_contents($_FILES['eml']['tmp_name']) ?: '';
    }
}

if ($domain === '' || !is_valid_domain($domain)) bail(400, 'Dominio mancante o non valido');
if (!is_valid_resolver($resolver))               bail(400, 'Resolver non valido (IP atteso)');

$extractedFromEml = [];
if ($emlContent !== '') {
    $extractedFromEml = extract_selectors_from_eml($emlContent);
}

if (!$selectors) {
    $selectors = $extractedFromEml ?: DEFAULT_SELECTORS;
}
$selectors = array_values(array_unique(array_filter($selectors, 'is_valid_selector')));
if (count($selectors) > 100) $selectors = array_slice($selectors, 0, 100);

// ---------- RUN ----------
$t0 = microtime(true);
$out = [
    'domain'                  => $domain,
    'resolver'                => $resolver,
    'timestamp'               => gmdate('c'),
    'eml_selectors_extracted' => $extractedFromEml,
    'selectors_used'          => $selectors,
    'mx'    => analyze_mx($resolver, $domain),
    'spf'   => analyze_spf($resolver, $domain),
    'dmarc' => analyze_dmarc($resolver, $domain),
    'dkim'  => analyze_dkim($resolver, $domain, $selectors),
];
$out['elapsed_ms'] = (int)round((microtime(true)-$t0)*1000);

$worst = 'ok';
foreach (['mx','spf','dmarc','dkim'] as $k) {
    $s = $out[$k]['status'] ?? 'ok';
    if ($s === 'critical') { $worst = 'critical'; break; }
    if ($s === 'warning' && $worst !== 'critical') $worst = 'warning';
}
$out['overall_status'] = $worst;

echo json_encode($out, JSON_UNESCAPED_SLASHES | JSON_PRETTY_PRINT);
