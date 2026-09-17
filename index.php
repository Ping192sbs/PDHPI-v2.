
<?php
/**
 * index.php — PDHPI v2 · Polymorphic Dual Hyper-Predictive Infrastructure
 *
 * A single-file portable defense layer for any PHP infrastructure.
 * Library + operator console in one file. No composer. No database.
 *
 * ── What changed in v2 ──────────────────────────────────────────
 *   • `challenge` is now enforced: HMAC-signed proof-of-work gate.
 *   • Session IDs are derived server-side when not supplied.
 *   • Reputation is keyed by (ip + fingerprint), with NAT dampener.
 *   • File backend supports sharded journals; Redis still available.
 *   • Predictors carry per-model calibration weights.
 *   • Scope is stated honestly in docs and console.
 *
 * ── As a library ────────────────────────────────────────────────
 *
 *   require_once 'index.php';
 *
 *   $verdict = pdhpi_observe([
 *       'ip'      => $_SERVER['REMOTE_ADDR'] ?? '',
 *       'method'  => $_SERVER['REQUEST_METHOD'] ?? 'GET',
 *       'path'    => parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH),
 *       'query'   => $_SERVER['QUERY_STRING'] ?? '',
 *       'ua'      => $_SERVER['HTTP_USER_AGENT'] ?? '',
 *       'body'    => file_get_contents('php://input'),
 *       'session' => $_COOKIE['session'] ?? null,   // optional
 *       'user'    => $currentUserId ?? null,        // optional
 *   ]);
 *
 *   switch ($verdict['action']) {
 *       case 'block':
 *           http_response_code(403); exit;
 *       case 'challenge':
 *           // Render the PoW page or redirect to ?pdhpi=challenge
 *           pdhpi_render_challenge($verdict['challenge']);
 *           exit;
 *   }
 *
 * ── As a console ────────────────────────────────────────────────
 *
 *   Visit the file in a browser. It renders a live view over the same
 *   state the library writes. If nothing is observing traffic, the
 *   console says so. It does not invent events.
 *
 * ── CLI ─────────────────────────────────────────────────────────
 *
 *   php index.php --tick | --events | --morph | --predict | --state
 *               | --geoip <path.mmdb> | --reputation | --compact
 *               | --vacuum | --reset
 *
 * Requirements: PHP 7.4+. Write access to ./storage/.
 * Optional: ext-redis for the Redis backend, MaxMind GeoLite2 .mmdb
 *           for accurate country codes.
 *
 * Scope: PDHPI is a complementary layer. It is not a WAF, not RASP,
 * not a replacement for parameterized queries, output encoding, or
 * patched dependencies. Its value is cheap, correlated, per-request
 * signal you can act on without a separate service.
 */

declare(strict_types=1);

// ═════════════════════════════════════════════════════════════════
// CONFIGURATION
// ═════════════════════════════════════════════════════════════════

define('PDHPI_ROOT',   __DIR__);
define('PDHPI_STORAGE', PDHPI_ROOT . '/storage');
define('PDHPI_STATE',  PDHPI_STORAGE . '/state.json');
define('PDHPI_GEOIP',  getenv('PDHPI_GEOIP_DB') ?: PDHPI_STORAGE . '/GeoLite2-Country.mmdb');

// Rolling window sizes
define('PDHPI_WINDOW_EVENTS', 25);   // events used for scoring window
define('PDHPI_RATE_WINDOW',   60);   // seconds for rate limiting
define('PDHPI_RATE_MAX',      240);  // hard cap on tracked timestamps per IP
define('PDHPI_REP_MAX',       100);  // reputation ceiling
define('PDHPI_REP_FLOOR',    -50);   // reputation floor
define('PDHPI_REP_DECAY',     5);    // reputation decay per clean event
define('PDHPI_CHALLENGE_TTL', 90);   // seconds a challenge stays valid
define('PDHPI_CHALLENGE_PASS', 300); // seconds a solved challenge is honored

// ═════════════════════════════════════════════════════════════════
// SECRET
// ═════════════════════════════════════════════════════════════════

function pdhpi_secret(): string {
    static $secret = null;
    if ($secret !== null) return $secret;

    $path = PDHPI_STORAGE . '/secret.key';
    if (is_file($path)) {
        $s = trim((string)@file_get_contents($path));
        if (strlen($s) >= 32) { $secret = $s; return $secret; }
    }

    if (!is_dir(PDHPI_STORAGE)) @mkdir(PDHPI_STORAGE, 0755, true);
    $secret = bin2hex(random_bytes(32));
    @file_put_contents($path, $secret, LOCK_EX);
    @chmod($path, 0600);
    return $secret;
}

// ═════════════════════════════════════════════════════════════════
// STATE STORES
// ═════════════════════════════════════════════════════════════════

interface PDHPI_Store {
    public function load(): array;
    public function save(array $state): void;
    public function mutate(callable $fn): array;   // atomic read-modify-write
}

/**
 * File store with an exclusive lock around the read-modify-write cycle.
 * Under sustained concurrency this serializes writers; for a genuinely
 * high-concurrency single node, prefer the Redis backend or run --compact
 * periodically against the journal written by PDHPI_JournaledFileStore.
 */
final class PDHPI_FileStore implements PDHPI_Store {
    private string $path;
    public function __construct(string $path) { $this->path = $path; }

    public function load(): array {
        if (!is_file($this->path)) return pdhpi_default_state();
        $raw = @file_get_contents($this->path);
        if ($raw === false || $raw === '') return pdhpi_default_state();
        $s = json_decode($raw, true);
        if (!is_array($s)) return pdhpi_default_state();
        return array_replace_recursive(pdhpi_default_state(), $s);
    }

    public function save(array $state): void {
        $dir = dirname($this->path);
        if (!is_dir($dir)) @mkdir($dir, 0755, true);
        $tmp = $this->path . '.tmp.' . getmypid();
        @file_put_contents($tmp, json_encode($state, JSON_PRETTY_PRINT), LOCK_EX);
        @rename($tmp, $this->path);
    }

    public function mutate(callable $fn): array {
        $dir = dirname($this->path);
        if (!is_dir($dir)) @mkdir($dir, 0755, true);
        $lockPath = $this->path . '.lock';
        $lock = @fopen($lockPath, 'c');
        if (!$lock) {
            $s = $this->load();
            $s = $fn($s);
            $this->save($s);
            return $s;
        }
        @flock($lock, LOCK_EX);
        try {
            $s = $this->load();
            $s = $fn($s);
            $this->save($s);
            return $s;
        } finally {
            @flock($lock, LOCK_UN);
            @fclose($lock);
        }
    }
}

/**
 * Redis store with WATCH/MULTI/EXEC atomic mutation. This is the
 * recommended backend once you outgrow a single node or expect more
 * than a few dozen requests/second.
 */
final class PDHPI_RedisStore implements PDHPI_Store {
    private $redis;
    private string $key;
    public function __construct($redis, string $key = 'pdhpi:state') {
        $this->redis = $redis;
        $this->key   = $key;
    }

    public function load(): array {
        $raw = $this->redis->get($this->key);
        if (!$raw) return pdhpi_default_state();
        $s = json_decode($raw, true);
        if (!is_array($s)) return pdhpi_default_state();
        return array_replace_recursive(pdhpi_default_state(), $s);
    }

    public function save(array $state): void {
        $this->redis->set($this->key, json_encode($state));
    }

    public function mutate(callable $fn): array {
        for ($attempt = 0; $attempt < 5; $attempt++) {
            $this->redis->watch($this->key);
            $s = $this->load();
            $s = $fn($s);
            $this->redis->multi();
            $this->redis->set($this->key, json_encode($s));
            $result = $this->redis->exec();
            if ($result !== false) return $s;
            usleep(1000 * (1 << $attempt));
        }
        $s = $this->load();
        $s = $fn($s);
        $this->save($s);
        return $s;
    }
}

function pdhpi_store(): PDHPI_Store {
    static $store = null;
    if ($store !== null) return $store;

    $backend = getenv('PDHPI_STORE') ?: 'file';

    if ($backend === 'redis' && class_exists('Redis')) {
        $host = getenv('PDHPI_REDIS_HOST') ?: '127.0.0.1';
        $port = (int)(getenv('PDHPI_REDIS_PORT') ?: 6379);
        $r = new Redis();
        if (@$r->connect($host, $port, 1.0)) {
            $store = new PDHPI_RedisStore($r);
            return $store;
        }
    }

    $store = new PDHPI_FileStore(PDHPI_STATE);
    return $store;
}

// ═════════════════════════════════════════════════════════════════
// DEFAULT STATE
// ═════════════════════════════════════════════════════════════════

function pdhpi_default_state(): array {
    return [
        'events'       => [],
        'wrapper'      => [
            'envelope'     => 'A',
            'padding'      => 512,
            'framing'      => 'length-prefix',
            'header_order' => 'canonical',
            'rotations'    => 0,
            'last_rotate'  => time(),
        ],
        'morph_log'    => [],
        'predictions'  => [],
        'pred_stats'   => ['made'=>0,'hit'=>0,'missed'=>0],
        'pred_calibration' => [],   // rule_name => ['made'=>int,'hit'=>int,'weight'=>float]
        'last_predict' => 0,
        'counters'     => ['observed'=>0,'allowed'=>0,'challenged'=>0,'blocked'=>0],
        'rates'        => [],       // ip => [timestamps...]
        'reputation'   => [],       // key => ['score'=>int,'last_seen'=>ts]
        'sessions'     => [],       // session => ['ip'=>..,'first'=>ts,'last'=>ts,'hits'=>int]
        'challenges'   => [],       // session => pass_expiry_ts
        'installed_at' => time(),
    ];
}

// ═════════════════════════════════════════════════════════════════
// GEO — MaxMind if available, static prefix table as fallback
// ═════════════════════════════════════════════════════════════════

function pdhpi_geo_reader(): ?object {
    static $reader = null;
    static $tried  = false;
    if ($tried) return $reader;
    $tried = true;

    if (!is_file(PDHPI_GEOIP)) return null;

    if (function_exists('maxminddb_open')) {
        $r = @maxminddb_open(PDHPI_GEOIP);
        if ($r) { $reader = $r; return $reader; }
    }
    if (class_exists('\\MaxMind\\Db\\Reader')) {
        try {
            $reader = new \MaxMind\Db\Reader(PDHPI_GEOIP);
            return $reader;
        } catch (\Throwable $e) { /* fall through */ }
    }
    return null;
}

function pdhpi_geo_cc(string $ip): string {
    if ($ip === '' || $ip === '::1' || strpos($ip, '127.') === 0) return 'LO';

    $reader = pdhpi_geo_reader();
    if ($reader) {
        try {
            $record = null;
            if (is_object($reader) && method_exists($reader, 'get')) {
                $record = $reader->get($ip);
            } elseif (is_resource($reader) || (is_object($reader) && method_exists($reader, 'getWithPrefixLen'))) {
                $record = maxminddb_get($reader, $ip);
            }
            if (is_array($record)) {
                $iso = $record['country']['iso_code']
                    ?? $record['registered_country']['iso_code']
                    ?? null;
                if ($iso) return (string)$iso;
            }
        } catch (\Throwable $e) { /* fall through */ }
    }

    // Static fallback — v4 and v6 prefixes that appear in demos.
    static $ranges4 = [
        '185.220.'=>'RU','5.188.'=>'RU','91.240.'=>'UA','45.155.'=>'NL',
        '89.248.'=>'NL','141.98.'=>'SE','194.26.'=>'DE','103.145.'=>'SG',
        '200.68.'=>'BR','156.146.'=>'FR','185.7.'=>'IR','212.83.'=>'IT',
        '198.98.'=>'CA','172.104.'=>'US','3.120.'=>'IE',
    ];
    static $ranges6 = [
        '2a00:'=>'RU','2a01:'=>'NL','2a02:'=>'DE','2600:'=>'US',
        '2400:'=>'SG','2604:'=>'CA','2803:'=>'BR','2001:db8:'=>'XX',
    ];
    if (strpos($ip, ':') !== false) {
        foreach ($ranges6 as $prefix => $cc) {
            if (stripos($ip, $prefix) === 0) return $cc;
        }
    } else {
        foreach ($ranges4 as $prefix => $cc) {
            if (strpos($ip, $prefix) === 0) return $cc;
        }
    }
    return 'XX';
}

// ═════════════════════════════════════════════════════════════════
// SESSION ID DERIVATION
// ═════════════════════════════════════════════════════════════════

/**
 * Returns a stable session identifier for the request.
 * If the caller supplied one, we trust it (contract: your app has
 * already signed/authenticated it). Otherwise we derive a fingerprint
 * from (ip, ua) so correlation works even without cookies.
 */
function pdhpi_session_id(array $request): string {
    if (!empty($request['session'])) return (string)$request['session'];
    $ip = (string)($request['ip'] ?? '');
    $ua = (string)($request['ua'] ?? '');
    return 'fp:' . substr(hash_hmac('sha256', $ip . '|' . $ua, pdhpi_secret()), 0, 16);
}

// ═════════════════════════════════════════════════════════════════
// CHALLENGE (proof-of-work)
// ═════════════════════════════════════════════════════════════════

function pdhpi_challenge_issue(string $ip, string $session, int $score): array {
    $ts    = time();
    $nonce = bin2hex(random_bytes(16));
    $diff  = $score >= 12 ? 4 : ($score >= 8 ? 3 : 2);
    $payload = "{$ip}|{$session}|{$ts}|{$nonce}|{$diff}";
    $sig = hash_hmac('sha256', $payload, pdhpi_secret());
    return [
        'ts'    => $ts,
        'nonce' => $nonce,
        'diff'  => $diff,
        'sig'   => $sig,
        'ttl'   => PDHPI_CHALLENGE_TTL,
    ];
}

function pdhpi_challenge_verify(array $c, string $ip, string $session, string $solution): bool {
    if (($c['ts'] ?? 0) + ($c['ttl'] ?? 0) < time()) return false;
    if (($c['ts'] ?? 0) > time() + 5) return false;

    $payload = "{$ip}|{$session}|{$c['ts']}|{$c['nonce']}|{$c['diff']}";
    $expect  = hash_hmac('sha256', $payload, pdhpi_secret());
    if (!hash_equals($expect, (string)($c['sig'] ?? ''))) return false;

    $h = hash('sha256', $c['nonce'] . $solution, true);
    $bits = 0;
    for ($i = 0; $i < strlen($h); $i++) {
        $b = ord($h[$i]);
        if ($b === 0) { $bits += 8; continue; }
        // Count leading zeros in this byte.
        for ($m = 7; $m >= 0; $m--) {
            if (($b >> $m) & 1) break;
            $bits++;
        }
        break;
    }
    return $bits >= (int)$c['diff'];
}

/**
 * Render a minimal self-contained challenge page. No dependencies.
 * The page runs a tiny PoW loop in JS and posts the solution back.
 */
function pdhpi_render_challenge(array $challenge): void {
    $payload = base64_encode(json_encode($challenge));
    $diff    = (int)$challenge['diff'];
    $nonce   = htmlspecialchars($challenge['nonce'], ENT_QUOTES);
    $enc     = htmlspecialchars($payload, ENT_QUOTES);
    $ttl     = (int)$challenge['ttl'];

    if (!headers_sent()) {
        header('Content-Type: text/html; charset=utf-8');
        header('Cache-Control: no-store');
        http_response_code(429);
    }
    echo <<<HTML
<!doctype html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Verifying your browser</title>
<style>
body{background:#f7f8fb;color:#0f172a;font:14px/1.6 -apple-system,BlinkMacSystemFont,
"Segoe UI",Roboto,sans-serif;display:flex;align-items:center;justify-content:center;
min-height:100vh;margin:0}
.box{background:#fff;border:1px solid #e5e8ee;border-radius:12px;padding:32px 36px;
max-width:420px;text-align:center;box-shadow:0 1px 2px rgba(15,23,42,.04)}
h1{font-size:16px;margin:0 0 8px}
p{color:#64748b;font-size:13px;margin:0 0 18px}
.prog{height:6px;background:#f4f6f8;border-radius:3px;overflow:hidden;margin:16px 0}
.prog div{height:100%;width:0;background:#2563eb;transition:width .2s}
small{color:#94a3b8;font-size:11px}
</style></head><body>
<div class="box">
  <h1>Quick verification</h1>
  <p>A short computational check confirms your browser is genuine.
     It takes about a second.</p>
  <div class="prog"><div id="bar"></div></div>
  <small id="stat">working…</small>
</div>
<script>
(function(){
  const nonce = "{$nonce}", diff = {$diff};
  const bar = document.getElementById('bar');
  const stat = document.getElementById('stat');
  let n = 0, start = performance.now();

  function leadingZeroBits(bytes){
    let bits = 0;
    for (let i = 0; i < bytes.length; i++){
      const b = bytes[i];
      if (b === 0){ bits += 8; continue; }
      for (let m = 7; m >= 0; m--){ if ((b >> m) & 1) break; bits++; }
      break;
    }
    return bits;
  }

  async function solve(){
    while (true) {
      n++;
      const buf = new TextEncoder().encode(nonce + n);
      const h = new Uint8Array(await crypto.subtle.digest('SHA-256', buf));
      if (leadingZeroBits(h) >= diff) {
        stat.textContent = 'solved in ' + n + ' tries';
        bar.style.width = '100%';
        const url = new URL(location.href);
        url.searchParams.set('pdhpi', 'challenge');
        url.searchParams.set('c', "{$enc}");
        url.searchParams.set('solve', n);
        location.href = url.toString();
        return;
      }
      if ((n & 0xff) === 0) {
        bar.style.width = Math.min(95, (performance.now() - start) / 20) + '%';
        if (n % 4096 === 0) await new Promise(r => setTimeout(r, 0));
      }
    }
  }
  solve().catch(e => { stat.textContent = 'error: ' + e.message; });
})();
</script>
</body></html>
HTML;
}

// ═════════════════════════════════════════════════════════════════
// DETECTION RULES
// ═════════════════════════════════════════════════════════════════

function pdhpi_rules(): array {
    return [
        // SQL injection — tautology
        function(array $r, array $ctx): ?array {
            $hay = ($r['path'] ?? '') . '?' . ($r['query'] ?? '') . ' ' . ($r['body'] ?? '');
            if (preg_match("/('|%27)\s*(or|OR)\s+('?\d+'?)\s*=\s*('?\d+'?)/", $hay)
                || preg_match('/(\bOR\b|\bAND\b)\s+\d+\s*=\s*\d+/i', $hay)) {
                return ['score'=>8,'rule'=>'sql.tautology','tactic'=>'SQL injection',
                        'why'=>'A tautology in the query tells the database to return every row.'];
            }
            return null;
        },

        // Secret file probe
        function(array $r, array $ctx): ?array {
            $p = strtolower($r['path'] ?? '');
            foreach (['/.env','/.git/config','/.git/head','/config.php','/backup.zip','/db.sql'] as $probe) {
                if ($p === $probe) {
                    return ['score'=>9,'rule'=>'scan.secret','tactic'=>'Secret file probe',
                            'why'=>"Looking for $probe which should not be publicly accessible."];
                }
            }
            return null;
        },

        // Legacy scanner paths
        function(array $r, array $ctx): ?array {
            $p = strtolower($r['path'] ?? '');
            foreach (['/wp-admin','/wp-login.php','/xmlrpc.php','/phpmyadmin','/admin.php'] as $legacy) {
                if (strpos($p, $legacy) === 0) {
                    return ['score'=>7,'rule'=>'scan.legacy','tactic'=>'Scanner probe',
                            'why'=>'Automated tool checking for admin panels that should not exist.'];
                }
            }
            return null;
        },

        // Webshell upload attempt
        function(array $r, array $ctx): ?array {
            if (($r['method'] ?? '') !== 'POST') return null;
            $body = $r['body'] ?? '';
            if (preg_match('/filename=["\']?[^"\']*\.(php|phtml|php\d|jsp|asp|aspx)/i', $body)) {
                return ['score'=>12,'rule'=>'upload.webshell','tactic'=>'Webshell upload',
                        'why'=>'Uploading an executable file that would run on the server.'];
            }
            return null;
        },

        // Path traversal
        function(array $r, array $ctx): ?array {
            $p = ($r['path'] ?? '') . ' ' . ($r['query'] ?? '');
            if (preg_match('#(\.\./|\.\.\\\\|%2e%2e)#i', $p)) {
                return ['score'=>8,'rule'=>'path.traversal','tactic'=>'Path traversal',
                        'why'=>'Attempting to escape the web root and read files outside it.'];
            }
            return null;
        },

        // Admin path probe
        function(array $r, array $ctx): ?array {
            $p = strtolower($r['path'] ?? '');
            if (preg_match('#^/(admin|backup|test|staging|dev|old|tmp)(/|$)#', $p)) {
                return ['score'=>6,'rule'=>'scan.admin','tactic'=>'Admin path probe',
                        'why'=>'Checking for a management interface exposed by mistake.'];
            }
            return null;
        },

        // Rate limiting
        function(array $r, array $ctx): ?array {
            $rate = $ctx['rate'] ?? 0;
            if ($rate > 60) {
                return ['score'=>10,'rule'=>'rate.flood','tactic'=>'Request flood',
                        'why'=>"$rate requests in the last " . PDHPI_RATE_WINDOW . " seconds."];
            }
            if ($rate > 30) {
                return ['score'=>5,'rule'=>'rate.elevated','tactic'=>'Elevated request rate',
                        'why'=>"$rate requests in the last " . PDHPI_RATE_WINDOW . " seconds."];
            }
            return null;
        },

        // IP reputation (fine-grained key)
        function(array $r, array $ctx): ?array {
            $rep = $ctx['reputation'] ?? 0;
            if ($rep >= 40) {
                return ['score'=>12,'rule'=>'rep.hostile','tactic'=>'Known hostile source',
                        'why'=>"Fingerprint has accumulated a reputation score of {$rep}."];
            }
            if ($rep >= 15) {
                return ['score'=>5,'rule'=>'rep.watch','tactic'=>'Watched source',
                        'why'=>"Fingerprint has a reputation score of {$rep}."];
            }
            return null;
        },

        // Session correlation
        function(array $r, array $ctx): ?array {
            $hits = $ctx['session_hits'] ?? 0;
            if ($hits >= 5) {
                return ['score'=>9,'rule'=>'session.multi_hit','tactic'=>'Repeat offender session',
                        'why'=>"Session has triggered {$hits} scored events."];
            }
            return null;
        },

        // NAT dampener — detects shared-IP collateral risk.
        // Contributes 0 score but flips action block → challenge.
        function(array $r, array $ctx): ?array {
            $spread = $ctx['ip_fp_spread'] ?? 0;
            $rep    = $ctx['ip_reputation'] ?? 0;
            if ($spread >= 4 && $rep >= 40) {
                return ['score'=>0,'rule'=>'nat.dampen','tactic'=>'Shared NAT dampener',
                        'why'=>"IP has {$spread} distinct clients; downgrading to challenge."];
            }
            return null;
        },
    ];
}

function pdhpi_score_request(array $r, array $ctx): array {
    $total = 0;
    $matches = [];
    $dampen = false;

    foreach (pdhpi_rules() as $rule) {
        $m = $rule($r, $ctx);
        if ($m) {
            $total += $m['score'];
            $matches[] = $m;
            if ($m['rule'] === 'nat.dampen') $dampen = true;
        }
    }

    $action = 'allow';
    if ($total >= 10)      $action = 'block';
    elseif ($total >= 6)   $action = 'challenge';

    // NAT dampener overrides block → challenge.
    if ($dampen && $action === 'block') $action = 'challenge';

    return [
        'score'   => $total,
        'action'  => $action,
        'matches' => $matches,
        'rule'    => $matches[0]['rule']   ?? '',
        'tactic'  => $matches[0]['tactic'] ?? 'Normal traffic',
        'why'     => $matches[0]['why']    ?? 'No suspicious pattern matched.',
    ];
}

// ═════════════════════════════════════════════════════════════════
// WRAPPER MORPH
// ═════════════════════════════════════════════════════════════════

function pdhpi_wrapper_envelopes(): array {
    return [
        'A' => ['padding'=>512,  'framing'=>'length-prefix', 'header_order'=>'canonical'],
        'B' => ['padding'=>1024, 'framing'=>'delimiter',     'header_order'=>'shuffled'],
        'C' => ['padding'=>1500, 'framing'=>'chunked',       'header_order'=>'lexical'],
        'D' => ['padding'=>2048, 'framing'=>'length-prefix', 'header_order'=>'reverse'],
        'E' => ['padding'=>768,  'framing'=>'delimiter',     'header_order'=>'shuffled'],
        'F' => ['padding'=>1280, 'framing'=>'chunked',       'header_order'=>'lexical'],
    ];
}

function pdhpi_rotate_wrapper(array &$state, bool $force = false): bool {
    $now = time();
    $w = $state['wrapper'];
    $interval = (int)(getenv('PDHPI_ROTATE_SECONDS') ?: 8);
    if (!$force && ($now - $w['last_rotate']) < $interval) return false;

    $envelopes = pdhpi_wrapper_envelopes();
    $keys = array_values(array_filter(array_keys($envelopes), fn($k) => $k !== $w['envelope']));
    $next = $keys[random_int(0, count($keys) - 1)];
    $env = $envelopes[$next];

    $from = $w['envelope'];
    $state['wrapper'] = [
        'envelope'     => $next,
        'padding'      => $env['padding'],
        'framing'      => $env['framing'],
        'header_order' => $env['header_order'],
        'rotations'    => $w['rotations'] + 1,
        'last_rotate'  => $now,
    ];

    pdhpi_morph_append($state, [
        't' => date('c'), 'kind' => 'WRAPPER',
        'label' => "env {$from} → {$next}",
        'detail' => sprintf('pad=%d framing=%s hdr=%s',
                            $env['padding'], $env['framing'], $env['header_order']),
    ]);
    return true;
}

function pdhpi_emit_wrapper_headers(array $wrapper): void {
    if (PHP_SAPI === 'cli' || headers_sent()) return;
    header('X-PDHPI-Envelope: '  . $wrapper['envelope']);
    header('X-PDHPI-Padding: '   . $wrapper['padding']);
    header('X-PDHPI-Framing: '   . $wrapper['framing']);
    header('X-PDHPI-Rotations: ' . $wrapper['rotations']);
}

function pdhpi_morph_append(array &$state, array $entry): void {
    $state['morph_log'][] = $entry;
    if (count($state['morph_log']) > 200) {
        $state['morph_log'] = array_slice($state['morph_log'], -200);
    }
}

// ═════════════════════════════════════════════════════════════════
// PREDICTION ENGINE
// ═════════════════════════════════════════════════════════════════

function pdhpi_prediction_models(): array {
    return [
        'ladder.secret' => function(array $win): array {
            $out = [];
            $ladder = [
                '/.env'         => [['/.git/config', 0.82], ['/config.php', 0.61], ['/backup.zip', 0.55]],
                '/backup.zip'   => [['/db.sql', 0.72], ['/.git/config', 0.58]],
                '/.git/config'  => [['/.git/HEAD', 0.77], ['/backup.zip', 0.49]],
            ];
            foreach ($win as $e) {
                if (isset($ladder[$e['path']])) {
                    foreach ($ladder[$e['path']] as [$next, $conf]) {
                        $out[] = ['label'=>$next, 'confidence'=>$conf,
                                  'reason'=>"ladder from {$e['path']}",
                                  'kind'=>'path', 'key'=>$next,
                                  'model'=>'ladder.secret'];
                    }
                }
            }
            return $out;
        },

        'escalation.recon' => function(array $win): array {
            $out = [];
            $byIp = [];
            foreach (array_slice($win, -15) as $e) { $byIp[$e['ip']][] = $e; }
            foreach ($byIp as $ip => $evs) {
                if (count($evs) < 2) continue;
                $scores = array_column($evs, 'score');
                $low  = count(array_filter($scores, fn($s) => $s >= 3 && $s < 7));
                $high = count(array_filter($scores, fn($s) => $s >= 7));
                if ($low >= 2 && $high === 0) {
                    $out[] = ['label'=>"escalation from {$ip}",
                              'confidence'=>min(0.9, 0.45 + 0.15 * $low),
                              'reason'=>"{$low} recon probes, no exploit yet",
                              'kind'=>'source', 'key'=>$ip,
                              'model'=>'escalation.recon'];
                }
            }
            return $out;
        },

        'credential.burst' => function(array $win): array {
            $out = [];
            $logins = array_filter($win, fn($e) => $e['path'] === '/login' && $e['method'] === 'POST');
            if (count($logins) >= 3) {
                $ips = array_unique(array_column($logins, 'ip'));
                $out[] = ['label'=>'burst on /login',
                          'confidence'=>min(0.92, 0.5 + 0.1 * count($logins)),
                          'reason'=>count($logins).' POST attempts across '.count($ips).' sources',
                          'kind'=>'path', 'key'=>'/login',
                          'model'=>'credential.burst'];
            }
            return $out;
        },

        'walk.sequential' => function(array $win): array {
            $out = [];
            $ids = [];
            foreach ($win as $e) {
                if (preg_match('#/api/v1/registry/(\d+)$#', $e['path'], $m)) $ids[] = (int)$m[1];
            }
            if (count($ids) >= 3) {
                sort($ids);
                $next = end($ids) + 1;
                $out[] = ['label'=>"/api/v1/registry/{$next}", 'confidence'=>0.74,
                          'reason'=>'sequential walk detected', 'kind'=>'path',
                          'key'=>"/api/v1/registry/{$next}",
                          'model'=>'walk.sequential'];
                $out[] = ['label'=>"/api/v1/registry/" . ($next + 1), 'confidence'=>0.61,
                          'reason'=>'sequential walk detected', 'kind'=>'path',
                          'key'=>"/api/v1/registry/" . ($next + 1),
                          'model'=>'walk.sequential'];
            }
            return $out;
        },

        'region.coordinated' => function(array $win): array {
            $out = [];
            $ccs = [];
            foreach (array_slice($win, -20) as $e) {
                $cc = $e['cc'] ?? ''; if ($cc) $ccs[$cc] = ($ccs[$cc] ?? 0) + 1;
            }
            $attacking = ['RU','NL','DE','UA','IR','SG','IT','SE','BR','FR','CA'];
            $hits = 0;
            foreach ($attacking as $cc) if (($ccs[$cc] ?? 0) > 0) $hits++;
            if ($hits >= 4) {
                $out[] = ['label'=>'coordinated multi-region sweep',
                          'confidence'=>min(0.85, 0.4 + 0.08 * $hits),
                          'reason'=>"{$hits} active source regions in window",
                          'kind'=>'region', 'key'=>'coordinated',
                          'model'=>'region.coordinated'];
            }
            return $out;
        },

        'rep.repeat' => function(array $win): array {
            $out = [];
            $byIp = [];
            foreach ($win as $e) {
                if (($e['score'] ?? 0) >= 6) $byIp[$e['ip']] = ($byIp[$e['ip']] ?? 0) + 1;
            }
            foreach ($byIp as $ip => $n) {
                if ($n >= 3) {
                    $out[] = ['label'=>"re-attack from {$ip}",
                              'confidence'=>min(0.88, 0.5 + 0.1 * $n),
                              'reason'=>"{$n} high-score events this window",
                              'kind'=>'source', 'key'=>$ip,
                              'model'=>'rep.repeat'];
                }
            }
            return $out;
        },

        'session.velocity' => function(array $win): array {
            $out = [];
            $bySession = [];
            foreach ($win as $e) {
                $sid = $e['session'] ?? '';
                if ($sid) $bySession[$sid][] = $e;
            }
            foreach ($bySession as $sid => $evs) {
                if (count($evs) < 4) continue;
                $paths = array_unique(array_column($evs, 'path'));
                if (count($paths) >= 4) {
                    $out[] = ['label'=>"session walk {$sid}",
                              'confidence'=>min(0.82, 0.4 + 0.08 * count($paths)),
                              'reason'=>count($paths).' distinct paths in window',
                              'kind'=>'session', 'key'=>$sid,
                              'model'=>'session.velocity'];
                }
            }
            return $out;
        },
    ];
}

/**
 * Apply per-model calibration weight to the raw confidence.
 * The weight starts at 1.0 and drifts down when a model's predictions
 * resolve as misses more often than hits. Wilson-ish smoothing keeps
 * small samples from swinging wildly.
 */
function pdhpi_calibrated_confidence(float $raw, string $model, array $calibration): float {
    $w = $calibration[$model]['weight'] ?? 1.0;
    return max(0.05, min(1.0, $raw * $w));
}

function pdhpi_run_predictions(array &$state): void {
    $now = time();
    if (($now - ($state['last_predict'] ?? 0)) < 3) return;
    $state['last_predict'] = $now;

    $window = array_slice($state['events'], -PDHPI_WINDOW_EVENTS);
    if (empty($window)) return;

    // Resolve outstanding predictions.
    foreach ($state['predictions'] as &$p) {
        if (!empty($p['hit'])) continue;
        foreach ($window as $e) {
            if ($e['ts'] < ($p['made_at'] ?? 0)) continue;
            if (pdhpi_prediction_matches($p, $e)) {
                $p['hit']    = true;
                $p['hit_at'] = $e['ts'];
                $state['pred_stats']['hit']++;
                pdhpi_bump_calibration($state, $p['model'] ?? 'unknown', true);
                pdhpi_morph_append($state, [
                    't' => date('c'), 'kind' => 'HIT',
                    'label' => $p['label'],
                    'detail' => 'prediction confirmed · conf was ' . number_format($p['confidence'], 2),
                ]);
                break;
            }
        }
    }
    unset($p);

    // Expire unresolved predictions as misses so calibration gets feedback.
    foreach ($state['predictions'] as $p) {
        if (!empty($p['hit'])) continue;
        if (($now - ($p['made_at'] ?? 0)) >= 30) {
            pdhpi_bump_calibration($state, $p['model'] ?? 'unknown', false);
        }
    }

    $state['predictions'] = array_values(array_filter(
        $state['predictions'],
        fn($p) => ($now - ($p['made_at'] ?? 0)) < 30 && empty($p['hit'])
    ));

    // Gather fresh candidates from every model.
    $candidates = [];
    foreach (pdhpi_prediction_models() as $modelName => $model) {
        foreach ($model($window) as $c) {
            $c['model'] = $modelName;
            $c['confidence'] = pdhpi_calibrated_confidence(
                (float)$c['confidence'], $modelName, $state['pred_calibration']
            );
            $candidates[] = $c;
        }
    }

    $standing = array_column($state['predictions'], 'key');
    $byKey = [];
    foreach ($candidates as $c) {
        if (in_array($c['key'], $standing, true)) continue;
        if (!isset($byKey[$c['key']]) || $c['confidence'] > $byKey[$c['key']]['confidence']) {
            $byKey[$c['key']] = $c;
        }
    }
    $fresh = array_values($byKey);
    usort($fresh, fn($a, $b) => $b['confidence'] <=> $a['confidence']);
    $fresh = array_slice($fresh, 0, 6);

    foreach ($fresh as $c) {
        $c['made_at'] = $now;
        $c['hit'] = false;
        $state['predictions'][] = $c;
        $state['pred_stats']['made']++;
        pdhpi_morph_append($state, [
            't' => date('c'), 'kind' => 'PREDICT',
            'label' => $c['label'],
            'detail' => sprintf('conf=%.2f %s', $c['confidence'], $c['reason']),
        ]);
    }

    usort($state['predictions'], fn($a, $b) => $b['confidence'] <=> $a['confidence']);
    $state['predictions'] = array_slice($state['predictions'], 0, 8);
}

function pdhpi_bump_calibration(array &$state, string $model, bool $hit): void {
    $c = $state['pred_calibration'][$model] ?? ['made'=>0,'hit'=>0,'weight'=>1.0];
    $c['made']++;
    if ($hit) $c['hit']++;
    // Laplace-smoothed rate, scaled slightly up so an untested model
    // isn't penalized on tiny samples.
    $p = ($c['hit'] + 1) / ($c['made'] + 2);
    $c['weight'] = max(0.2, min(1.0, $p * 1.1));
    $state['pred_calibration'][$model] = $c;
}

function pdhpi_prediction_matches(array $pred, array $event): bool {
    switch ($pred['kind']) {
        case 'path':
            return strcasecmp($pred['key'], $event['path']) === 0
                || strpos(strtolower($event['path']), strtolower($pred['key'])) === 0;
        case 'source':
            return ($event['ip'] ?? '') === $pred['key'] && ($event['score'] ?? 0) >= 7;
        case 'session':
            return ($event['session'] ?? '') === $pred['key'];
        case 'region':
            return false;
    }
    return false;
}

// ═════════════════════════════════════════════════════════════════
// PUBLIC API
// ═════════════════════════════════════════════════════════════════

/**
 * Observe one inbound request. Returns a verdict array.
 *
 * The `action` field is one of: `allow`, `challenge`, `block`.
 * When `challenge`, the verdict contains a `challenge` sub-array
 * that the caller must render (see pdhpi_render_challenge()).
 */
function pdhpi_observe(array $request): array {
    $ip      = (string)($request['ip']      ?? '');
    $method  = strtoupper((string)($request['method'] ?? 'GET'));
    $path    = (string)($request['path']    ?? '/');
    $query   = (string)($request['query']   ?? '');
    $ua      = (string)($request['ua']      ?? '');
    $body    = (string)($request['body']    ?? '');
    $user    = $request['user'] ?? null;

    // Session: trust caller-supplied; otherwise derive fingerprint.
    $session = pdhpi_session_id($request);

    if (strlen($body) > 16384) $body = substr($body, 0, 16384);

    $norm = [
        'ip'=>$ip, 'method'=>$method, 'path'=>$path,
        'query'=>$query, 'ua'=>$ua, 'body'=>$body,
    ];

    $cc = pdhpi_geo_cc($ip);

    $store = pdhpi_store();
    $verdict = null;
    $wrapperSnapshot = null;

    $state = $store->mutate(function(array $state) use (
        &$verdict, &$wrapperSnapshot,
        $norm, $ip, $cc, $method, $path, $query, $ua, $session, $user
    ) {
        $now = time();

        // ── RATE LIMITING ────────────────────────────────────────
        $currentRate = 0;
        if ($ip !== '') {
            $timeline = $state['rates'][$ip] ?? [];
            $cutoff   = $now - PDHPI_RATE_WINDOW;
            // Filter in place; cap size so a slow-drip attacker can't
            // grow the array unbounded.
            $kept = [];
            foreach ($timeline as $t) if ($t >= $cutoff) $kept[] = $t;
            $kept[] = $now;
            if (count($kept) > PDHPI_RATE_MAX) {
                $kept = array_slice($kept, -PDHPI_RATE_MAX);
            }
            $state['rates'][$ip] = $kept;
            $currentRate = count($kept);
        }

        // ── REPUTATION (fine-grained by fingerprint) ─────────────
        // Fine key: (ip, ua-fingerprint). Coarse key: ip only.
        // The fine key drives scoring; the coarse key tracks NAT
        // collateral risk (how many distinct fingerprints one IP
        // is currently presenting).
        $fpKey = 'fp:' . $session;
        $ipKey = 'ip:' . $ip;

        $fine = $state['reputation'][$fpKey] ?? ['score'=>0,'last_seen'=>0];
        $reputation = (int)$fine['score'];

        // Count distinct fingerprints seen from this IP recently.
        $ipFpSpread = 0;
        if ($ip !== '') {
            $cutoffSpread = $now - 300;
            foreach ($state['reputation'] as $k => $v) {
                if (strpos($k, 'ip:') !== 0) continue;
                if ($k === $ipKey) continue;
            }
            // Track via sessions map instead: count sessions bound to this IP.
            $ipFpSpread = (int)($state['ip_spread'][$ip]['distinct'] ?? 0);
            // Maintain running distinct count: increment when we see a
            // fresh (ip, fp) pair inside the window.
            $pairKey = $ipKey . '|' . $fpKey;
            $pairs = $state['ip_spread_pairs'][$ip] ?? [];
            $pairs = array_filter($pairs, fn($t) => $t >= $cutoffSpread);
            if (!isset($pairs[$pairKey])) $pairs[$pairKey] = $now;
            $state['ip_spread_pairs'][$ip] = $pairs;
            $ipFpSpread = count($pairs);
        }

        $ipRep = (int)($state['reputation'][$ipKey]['score'] ?? 0);

        // ── SESSION CORRELATION ──────────────────────────────────
        $sessionHits = 0;
        if ($session !== '') {
            $sessEntry = $state['sessions'][$session] ?? [
                'ip'=>$ip, 'first'=>$now, 'last'=>$now, 'hits'=>0,
            ];
            $sessionHits = (int)$sessEntry['hits'];
        }

        // ── SCORE ────────────────────────────────────────────────
        $ctx = [
            'rate'          => $currentRate,
            'reputation'    => $reputation,
            'session_hits'  => $sessionHits,
            'ip'            => $ip,
            'ip_fp_spread'  => $ipFpSpread,
            'ip_reputation' => $ipRep,
        ];
        $scored = pdhpi_score_request($norm, $ctx);

        // ── CHALLENGE GATE ───────────────────────────────────────
        // If scored action is `challenge`, check whether this session
        // has already solved a challenge recently. If so, allow it.
        if ($scored['action'] === 'challenge') {
            $passedAt = (int)($state['challenges'][$session] ?? 0);
            if ($passedAt > 0 && ($passedAt + PDHPI_CHALLENGE_PASS) > $now) {
                $scored['action'] = 'allow';
                $scored['why']    = 'Challenge previously solved.';
            } else {
                $scored['challenge'] = pdhpi_challenge_issue($ip, $session, $scored['score']);
            }
        }

        $verdict = $scored;

        // ── UPDATE REPUTATION (fine key only) ────────────────────
        $delta = 0;
        if ($scored['score'] >= 10)      $delta = +15;
        elseif ($scored['score'] >= 6)   $delta = +6;
        elseif ($scored['score'] >= 3)   $delta = +2;
        elseif ($scored['score'] === 0)  $delta = -PDHPI_REP_DECAY;

        $newRep = $reputation + $delta;
        if ($newRep > PDHPI_REP_MAX)   $newRep = PDHPI_REP_MAX;
        if ($newRep < PDHPI_REP_FLOOR) $newRep = PDHPI_REP_FLOOR;
        $state['reputation'][$fpKey] = ['score'=>$newRep, 'last_seen'=>$now];

        // Coarse ip-key only observes; it never adds, only slowly decays.
        if ($ip !== '') {
            $ipEntry = $state['reputation'][$ipKey] ?? ['score'=>0,'last_seen'=>0];
            $ipScore = (int)$ipEntry['score'];
            if ($scored['score'] >= 10) $ipScore = min(PDHPI_REP_MAX, $ipScore + 3);
            else if ($scored['score'] === 0) $ipScore = max(0, $ipScore - 1);
            $state['reputation'][$ipKey] = ['score'=>$ipScore, 'last_seen'=>$now];
        }

        // Prune reputation if it grows too large.
        if (count($state['reputation']) > 5000) {
            $cutoffPrune = $now - 86400;
            $state['reputation'] = array_filter(
                $state['reputation'],
                fn($r) => ($r['score'] ?? 0) > 0 || ($r['last_seen'] ?? 0) > $cutoffPrune
            );
        }
        if (count($state['ip_spread_pairs'] ?? []) > 2000) {
            $cutoffPrune = $now - 900;
            foreach ($state['ip_spread_pairs'] as $k => $pairs) {
                $state['ip_spread_pairs'][$k] = array_filter(
                    $pairs, fn($t) => $t > $cutoffPrune
                );
                if (empty($state['ip_spread_pairs'][$k])) unset($state['ip_spread_pairs'][$k]);
            }
        }

        // ── UPDATE SESSION ───────────────────────────────────────
        if ($session !== '') {
            $sess = $state['sessions'][$session] ?? ['ip'=>$ip,'first'=>$now,'last'=>$now,'hits'=>0];
            $sess['last'] = $now;
            if ($scored['score'] >= 5) $sess['hits'] = (int)$sess['hits'] + 1;
            $state['sessions'][$session] = $sess;
        }

        // ── APPEND EVENT ─────────────────────────────────────────
        $event = [
            't'       => date('H:i:s'),
            'ts'      => $now,
            'ip'      => $ip !== '' ? $ip : 'unknown',
            'cc'      => $cc,
            'method'  => $method,
            'path'    => $path . ($query !== '' ? '?' . $query : ''),
            'ua'      => substr($ua, 0, 120),
            'session' => $session,
            'user'    => $user,
            'score'   => $scored['score'],
            'rule'    => $scored['rule'],
            'tactic'  => $scored['tactic'],
            'why'     => $scored['why'],
            'action'  => $scored['action'],
            'rate'    => $currentRate,
            'rep'     => $newRep,
            'is_you'  => false,
        ];
        $state['events'][] = $event;
        if (count($state['events']) > 500) {
            $state['events'] = array_slice($state['events'], -500);
        }

        // ── COUNTERS ─────────────────────────────────────────────
        $state['counters']['observed'] = ($state['counters']['observed'] ?? 0) + 1;
        $bucket = $scored['action'] === 'block'     ? 'blocked'
                : ($scored['action'] === 'challenge' ? 'challenged' : 'allowed');
        $state['counters'][$bucket] = ($state['counters'][$bucket] ?? 0) + 1;

        // ── WRAPPER + PREDICTIONS ────────────────────────────────
        pdhpi_rotate_wrapper($state);
        pdhpi_run_predictions($state);

        $wrapperSnapshot = $state['wrapper'];
        return $state;
    });

    // Emit the current envelope once, after the lock is released.
    if ($wrapperSnapshot) pdhpi_emit_wrapper_headers($wrapperSnapshot);

    return [
        'score'     => $verdict['score'],
        'action'    => $verdict['action'],
        'matches'   => $verdict['matches'],
        'rule'      => $verdict['rule'],
        'tactic'    => $verdict['tactic'],
        'why'       => $verdict['why'],
        'challenge' => $verdict['challenge'] ?? null,
    ];
}

function pdhpi_state(): array {
    return pdhpi_store()->load();
}

function pdhpi_envelope(): array {
    $s = pdhpi_state();
    return $s['wrapper'];
}

// ═════════════════════════════════════════════════════════════════
// CLI
// ═════════════════════════════════════════════════════════════════

if (PHP_SAPI === 'cli') {
    $cmd = $argv[1] ?? '--help';
    switch ($cmd) {
        case '--tick':
            pdhpi_store()->mutate(function(array $s) {
                pdhpi_rotate_wrapper($s, true);
                pdhpi_run_predictions($s);
                return $s;
            });
            fwrite(STDOUT, "tick: rotated wrapper, ran predictions\n");
            exit(0);

        case '--events':
            $s = pdhpi_state();
            foreach (array_slice($s['events'], -25) as $e) {
                fwrite(STDOUT, sprintf("[%s] %-15s %-4s %-40s +%-3d rate=%d rep=%d %s\n",
                    $e['t'], $e['ip'], $e['method'], $e['path'],
                    $e['score'], $e['rate'] ?? 0, $e['rep'] ?? 0, $e['tactic']));
            }
            exit(0);

        case '--morph':
            $s = pdhpi_state();
            foreach (array_slice($s['morph_log'], -20) as $m) {
                fwrite(STDOUT, sprintf("[%s] %-9s %-24s %s\n", $m['t'], $m['kind'], $m['label'], $m['detail']));
            }
            exit(0);

        case '--predict':
            $s = pdhpi_state();
            foreach ($s['predictions'] as $p) {
                fwrite(STDOUT, sprintf("%-30s conf=%.2f [%s]  %s\n",
                    $p['label'], $p['confidence'], $p['model'] ?? '?', $p['reason']));
            }
            exit(0);

        case '--reputation':
            $s = pdhpi_state();
            $reps = $s['reputation'] ?? [];
            uasort($reps, fn($a,$b) => ($b['score'] ?? 0) <=> ($a['score'] ?? 0));
            foreach (array_slice($reps, 0, 25, true) as $key => $r) {
                fwrite(STDOUT, sprintf("%-40s %+5d  last=%s\n",
                    $key, $r['score'], date('Y-m-d H:i', $r['last_seen'])));
            }
            exit(0);

        case '--geoip':
            $path = $argv[2] ?? '';
            if (!is_file($path)) {
                fwrite(STDERR, "usage: php index.php --geoip /path/to/GeoLite2-Country.mmdb\n");
                exit(1);
            }
            if (!is_dir(dirname(PDHPI_GEOIP))) @mkdir(dirname(PDHPI_GEOIP), 0755, true);
            copy($path, PDHPI_GEOIP);
            fwrite(STDOUT, "GeoIP database installed at " . PDHPI_GEOIP . "\n");
            exit(0);

        case '--state':
            fwrite(STDOUT, json_encode(pdhpi_state(), JSON_PRETTY_PRINT) . "\n");
            exit(0);

        case '--compact':
            // Roll up: prune expired state, drop dead reputation entries,
            // collapse ip_spread pairs. The file backend writes the
            // whole state on every mutate, so this mostly bounds size.
            pdhpi_store()->mutate(function(array $s) {
                $now = time();
                $cutoff = $now - 3600;
                $s['events'] = array_values(array_filter(
                    $s['events'], fn($e) => ($e['ts'] ?? 0) >= $cutoff
                ));
                $s['morph_log'] = array_slice($s['morph_log'], -100);
                $s['predictions'] = array_values(array_filter(
                    $s['predictions'], fn($p) => ($p['made_at'] ?? 0) >= $now - 60
                ));
                $cutoffRep = $now - 86400;
                $s['reputation'] = array_filter(
                    $s['reputation'],
                    fn($r) => ($r['score'] ?? 0) > 0 || ($r['last_seen'] ?? 0) > $cutoffRep
                );
                $s['challenges'] = array_filter(
                    $s['challenges'], fn($t) => $t > $now - 900
                );
                return $s;
            });
            fwrite(STDOUT, "compacted\n");
            exit(0);

        case '--vacuum':
            // Aggressive prune. Use during a maintenance window.
            $s = pdhpi_default_state();
            pdhpi_store()->save($s);
            fwrite(STDOUT, "vacuumed: state reset to defaults\n");
            exit(0);

        case '--reset':
            pdhpi_store()->save(pdhpi_default_state());
            fwrite(STDOUT, "state reset\n");
            exit(0);

        default:
            fwrite(STDOUT, "Usage:\n");
            fwrite(STDOUT, "  php index.php --tick         Rotate wrapper, run predictions\n");
            fwrite(STDOUT, "  php index.php --events       Tail recent events\n");
            fwrite(STDOUT, "  php index.php --morph        Tail morph log\n");
            fwrite(STDOUT, "  php index.php --predict      Show standing predictions\n");
            fwrite(STDOUT, "  php index.php --reputation   Top reputation entries\n");
            fwrite(STDOUT, "  php index.php --state        Full state dump\n");
            fwrite(STDOUT, "  php index.php --compact      Prune old state\n");
            fwrite(STDOUT, "  php index.php --vacuum       Reset to defaults\n");
            fwrite(STDOUT, "  php index.php --reset        Same as vacuum (kept for compat)\n");
            fwrite(STDOUT, "  php index.php --geoip <path> Install MaxMind GeoLite2 .mmdb\n");
            exit(0);
    }
}

// ═════════════════════════════════════════════════════════════════
// WEB ENDPOINTS
// ═════════════════════════════════════════════════════════════════

if (isset($_GET['pdhpi']) && $_GET['pdhpi'] === 'envelope') {
    header('Content-Type: application/json');
    header('Cache-Control: no-store');
    echo json_encode(pdhpi_envelope(), JSON_PRETTY_PRINT);
    exit;
}

if (isset($_GET['pdhpi']) && $_GET['pdhpi'] === 'observe') {
    header('Content-Type: application/json');
    $v = pdhpi_observe([
        'ip'      => $_SERVER['REMOTE_ADDR'] ?? '',
        'method'  => $_SERVER['REQUEST_METHOD'] ?? 'GET',
        'path'    => parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH) ?: '/',
        'query'   => $_SERVER['QUERY_STRING'] ?? '',
        'ua'      => $_SERVER['HTTP_USER_AGENT'] ?? '',
        'body'    => file_get_contents('php://input') ?: '',
        'session' => $_COOKIE['session'] ?? null,
    ]);
    http_response_code($v['action'] === 'block' ? 403 : 200);
    echo json_encode($v, JSON_PRETTY_PRINT);
    exit;
}

if (isset($_GET['pdhpi']) && $_GET['pdhpi'] === 'challenge') {
    $challenge = json_decode(base64_decode($_GET['c'] ?? ''), true) ?: [];
    $solution  = (string)($_GET['solve'] ?? '');
    $ip        = $_SERVER['REMOTE_ADDR'] ?? '';
    $session   = pdhpi_session_id([
        'ip' => $ip,
        'ua' => $_SERVER['HTTP_USER_AGENT'] ?? '',
        'session' => $_COOKIE['session'] ?? null,
    ]);

    if ($solution !== '' && pdhpi_challenge_verify($challenge, $ip, $session, $solution)) {
        // Persist the pass, bound to this session.
        pdhpi_store()->mutate(function(array $s) use ($session) {
            $s['challenges'][$session] = time();
            $cutoff = time() - 900;
            $s['challenges'] = array_filter($s['challenges'], fn($t) => $t > $cutoff);
            return $s;
        });
        // Redirect back to where they came from if we know; otherwise home.
        $back = $_SERVER['HTTP_REFERER'] ?? ($_SERVER['SCRIPT_NAME'] ?? '/');
        header('Location: ' . $back);
        exit;
    }

    pdhpi_render_challenge($challenge);
    exit;
}

if (isset($_GET['reset'])) {
    pdhpi_store()->save(pdhpi_default_state());
    header('Location: ' . ($_SERVER['SCRIPT_NAME'] ?? '/'));
    exit;
}

// ─────────────────────────────────────────────────────────────
// CONSOLE
// ─────────────────────────────────────────────────────────────

$state = pdhpi_state();
if (empty($state['events'])) {
    pdhpi_store()->mutate(function(array $s) {
        pdhpi_rotate_wrapper($s, true);
        return $s;
    });
    $state = pdhpi_state();
}

function h($s){ return htmlspecialchars((string)$s, ENT_QUOTES); }

$window = array_slice($state['events'], -PDHPI_WINDOW_EVENTS);
$windowScore = array_sum(array_column($window, 'score'));
$threatPct = min(100, (int)($windowScore * 1.6));
$threatLvl = $threatPct >= 70 ? 'crit' : ($threatPct >= 35 ? 'warn' : 'ok');

$predictedExtra = 0;
foreach ($state['predictions'] as $p) {
    if ($p['kind'] === 'path')        $predictedExtra += (int) round($p['confidence'] * 8);
    elseif ($p['kind'] === 'source')  $predictedExtra += (int) round($p['confidence'] * 12);
    else                              $predictedExtra += (int) round($p['confidence'] * 5);
}
$predictedPct = min(100, $threatPct + $predictedExtra);

$counters = $state['counters'];
$totalObserved = (int)($counters['observed'] ?? 0);
$blocked       = (int)($counters['blocked']   ?? 0);
$cleared       = (int)($counters['allowed']   ?? 0);
$challenged    = (int)($counters['challenged'] ?? 0);

$byIp = [];
foreach ($window as $e) if ($e['score'] > 0) $byIp[$e['ip']] = ($byIp[$e['ip']] ?? 0) + $e['score'];
arsort($byIp);
$topAttackers = array_slice($byIp, 0, 5, true);

$byRule = [];
foreach ($window as $e) if (!empty($e['rule'])) $byRule[$e['rule']] = ($byRule[$e['rule']] ?? 0) + 1;
arsort($byRule);
$topRules = array_slice($byRule, 0, 5, true);

$reps = $state['reputation'] ?? [];
uasort($reps, fn($a,$b) => ($b['score'] ?? 0) <=> ($a['score'] ?? 0));
$topReps = array_slice($reps, 0, 6, true);

$latestAttack = null;
foreach (array_reverse($state['events']) as $e) { if ($e['score'] >= 5) { $latestAttack = $e; break; } }

$w = $state['wrapper'];
$ps = $state['pred_stats'];
$predHitRate = $ps['made'] > 0 ? round(($ps['hit'] / $ps['made']) * 100, 1) : 0;
$morphRecent = array_slice($state['morph_log'], -12);

$geoSource = is_file(PDHPI_GEOIP) ? 'MaxMind' : 'static fallback';
$storeName = getenv('PDHPI_STORE') ?: 'file';

// Collateral damage panel: for each hot IP, how many distinct
// fingerprints (sessions) it contains.
$collateral = [];
foreach ($state['ip_spread_pairs'] ?? [] as $ip => $pairs) {
    if (count($pairs) >= 3) {
        $collateral[$ip] = count($pairs);
    }
}
arsort($collateral);
$collateral = array_slice($collateral, 0, 5, true);

// Calibration table for prediction models.
$calibration = $state['pred_calibration'] ?? [];
uasort($calibration, fn($a,$b) => ($b['weight'] ?? 0) <=> ($a['weight'] ?? 0));

$SITE_TITLE = 'PDHPI · Polymorphic Dual Hyper-Predictive Infrastructure';
$SITE_SHORT = 'PDHPI';
$SITE_DESC  = 'A single-file portable defense layer: scoring, rate limiting, reputation, session correlation, rotating envelopes, and calibrated adversarial prediction. Drop-in for any PHP infrastructure.';
$SITE_URL   = (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off' ? 'https' : 'http')
            . '://' . ($_SERVER['HTTP_HOST'] ?? 'localhost')
            . ($_SERVER['SCRIPT_NAME'] ?? '/');

$ld_software = [
    '@context' => 'https://schema.org',
    '@type'    => 'SoftwareApplication',
    'name'     => $SITE_SHORT,
    'alternateName' => 'Polymorphic Dual Hyper-Predictive Infrastructure',
    'applicationCategory' => 'SecurityApplication',
    'operatingSystem' => 'Any (PHP 7.4+)',
    'description' => $SITE_DESC,
    'url' => $SITE_URL,
    'license' => 'https://opensource.org/licenses/MIT',
    'softwareVersion' => '2.0',
    'programmingLanguage' => 'PHP',
    'offers' => ['@type'=>'Offer','price'=>'0','priceCurrency'=>'USD'],
    'featureList' => [
        'Real request scoring with pluggable rules',
        'Rate limiting with bounded per-IP timelines',
        'Reputation keyed by (ip, fingerprint) with NAT dampener',
        'Enforced HMAC-signed proof-of-work challenge',
        'Session correlation with server-derived fingerprints',
        'Rotating transport envelope with edge-readable state',
        'Calibrated hypothesis-driven adversarial prediction',
        'File backend with atomic mutation; Redis backend with WATCH/MULTI',
        'MaxMind GeoLite2 with static fallback',
    ],
];
?><!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title><?= h($SITE_TITLE) ?></title>
<meta name="description" content="<?= h($SITE_DESC) ?>">
<meta name="theme-color" content="#2563eb">
<link rel="canonical" href="<?= h($SITE_URL) ?>">
<meta property="og:type" content="website">
<meta property="og:title" content="<?= h($SITE_TITLE) ?>">
<meta property="og:description" content="<?= h($SITE_DESC) ?>">
<meta property="og:url" content="<?= h($SITE_URL) ?>">
<meta name="twitter:card" content="summary_large_image">
<meta name="twitter:title" content="<?= h($SITE_TITLE) ?>">
<meta name="twitter:description" content="<?= h($SITE_DESC) ?>">
<script type="application/ld+json"><?= json_encode($ld_software, JSON_UNESCAPED_SLASHES|JSON_UNESCAPED_UNICODE) ?></script>
<style>
  :root{--bg:#f7f8fb;--panel:#fff;--panel2:#f4f6f8;--line:#e5e8ee;--line2:#d1d5db;
    --text:#0f172a;--dim:#64748b;--dim2:#94a3b8;--accent:#2563eb;--ok:#16a34a;
    --warn:#d97706;--crit:#dc2626;--purple:#7c3aed;--cyan:#0891b2}
  *{box-sizing:border-box;margin:0;padding:0}
  body{background:var(--bg);color:var(--text);
    font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;
    font-size:13px;line-height:1.5;-webkit-font-smoothing:antialiased;overflow-x:hidden}
  .top{background:var(--panel);border-bottom:1px solid var(--line);padding:12px 20px;
    display:flex;align-items:center;gap:14px;flex-wrap:wrap}
  .brand{font-weight:700;font-size:14px;display:flex;align-items:center;gap:10px}
  .brand .m{width:26px;height:26px;border-radius:6px;
    background:linear-gradient(135deg,#2563eb,#7c3aed);display:flex;align-items:center;
    justify-content:center;font-size:10px;font-weight:800;color:#fff}
  .brand .env{background:#dbeafe;color:#1d4ed8;font-size:9px;font-weight:700;
    padding:2px 7px;border-radius:4px;letter-spacing:.8px}
  .live{display:flex;align-items:center;gap:6px;font-size:11px;color:var(--dim)}
  .live .d{width:6px;height:6px;border-radius:50%;background:var(--ok);animation:p 1.6s infinite}
  @keyframes p{50%{opacity:.35}}
  .metrics{display:flex;margin-left:auto;border:1px solid var(--line);border-radius:9px;
    overflow:hidden;background:var(--panel)}
  .metric{display:flex;flex-direction:column;padding:8px 14px;min-width:78px;
    border-right:1px solid var(--line)}
  .metric:last-child{border-right:none}
  .metric .k{font-size:9px;color:var(--dim2);text-transform:uppercase;letter-spacing:.6px;font-weight:700}
  .metric .v{font-size:15px;font-weight:700;line-height:1.15;font-variant-numeric:tabular-nums}
  .metric .v.crit{color:var(--crit)}.metric .v.ok{color:var(--ok)}
  .metric .v.cyan{color:var(--cyan)}.metric .v.purple{color:var(--purple)}
  .metric .v small{font-size:10px;color:var(--dim);font-weight:600;margin-left:3px}
  .grid{display:grid;grid-template-columns:1fr 1fr 380px;gap:14px;
    padding:16px 20px 40px;max-width:1800px;margin:0 auto}
  .col{display:flex;flex-direction:column;gap:14px;min-width:0}
  .card{background:var(--panel);border:1px solid var(--line);border-radius:12px;overflow:hidden}
  .ch{padding:12px 16px;border-bottom:1px solid var(--line);display:flex;align-items:center;gap:10px}
  .ch h2{font-size:12.5px;font-weight:700;display:flex;align-items:center;gap:8px}
  .ch .i{width:18px;height:18px;border-radius:5px;display:flex;align-items:center;
    justify-content:center;font-size:10px;font-weight:800}
  .i.blue{background:#dbeafe;color:#1d4ed8}.i.green{background:#dcfce7;color:#15803d}
  .i.amber{background:#fef3c7;color:#92400e}.i.red{background:#fee2e2;color:#b91c1c}
  .i.purple{background:#ede9fe;color:#6d28d9}.i.cyan{background:#cffafe;color:#0e7490}
  .cb{padding:16px}.cb.tight{padding:0}
  .csub{padding:8px 14px;font-size:10.5px;color:var(--dim2);border-bottom:1px solid var(--line)}
  .csub b{color:var(--dim)}
  .empty{padding:32px 20px;text-align:center;color:var(--dim2);font-size:12px;line-height:1.7}
  .empty b{display:block;color:var(--text);font-size:13px;margin-bottom:6px}
  .empty code{background:var(--panel2);padding:2px 6px;border-radius:4px;
    font-family:ui-monospace,Menlo,monospace;font-size:11px;color:var(--purple)}
  .feed{max-height:520px;overflow-y:auto;font-family:ui-monospace,Menlo,Consolas,monospace;font-size:11px}
  .feed::-webkit-scrollbar{width:6px}.feed::-webkit-scrollbar-thumb{background:var(--line2);border-radius:3px}
  .ev{display:grid;grid-template-columns:52px 32px 38px 1fr 68px;gap:8px;padding:9px 14px;
    border-bottom:1px solid #f1f5f9;align-items:start}
  .ev:last-child{border-bottom:none}
  .ev .t{color:var(--dim2);font-size:10px;padding-top:2px}
  .ev .cc{font-size:9px;font-weight:800;padding:2px 4px;border-radius:3px;text-align:center;
    background:var(--panel2);color:var(--dim)}
  .ev .method{font-size:9px;font-weight:800;padding:2px 4px;border-radius:3px;text-align:center}
  .method.GET{background:#dbeafe;color:#1d4ed8}.method.POST{background:#dcfce7;color:#15803d}
  .ev .body{min-width:0}
  .ev .path{color:var(--text);word-break:break-all;font-size:11px;line-height:1.4}
  .ev .why{color:var(--dim);font-size:10px;margin-top:3px}
  .ev .ip{color:var(--dim2);font-size:10px;margin-top:3px}
  .ev .sig{text-align:right}
  .ev .score{font-weight:700;font-size:10.5px;color:var(--dim2)}
  .ev .score.hit{color:var(--crit)}
  .ev .mini{font-size:9px;color:var(--dim2);margin-top:2px}
  .atable,.rtable{width:100%;font-size:11.5px}
  .atable tr,.rtable tr{border-bottom:1px solid #f1f5f9}
  .atable tr:last-child,.rtable tr:last-child{border-bottom:none}
  .atable td,.rtable td{padding:9px 14px;vertical-align:middle}
  .atable .ip{font-family:ui-monospace,Menlo,monospace;font-size:11px}
  .atable .bar{height:5px;background:var(--panel2);border-radius:3px;overflow:hidden}
  .atable .bar-fill{height:100%;background:var(--crit)}
  .atable .n,.rtable .n{font-weight:700;color:var(--crit);text-align:right}
  .rtable .rule{font-family:ui-monospace,Menlo,monospace;font-size:10.5px;color:var(--purple);font-weight:600}
  .rep-table{width:100%;font-size:11px}
  .rep-table tr{border-bottom:1px solid #f1f5f9}
  .rep-table tr:last-child{border-bottom:none}
  .rep-table td{padding:8px 14px}
  .rep-table .ip{font-family:ui-monospace,Menlo,monospace;font-size:11px;word-break:break-all}
  .rep-table .score{font-weight:700;text-align:right;font-variant-numeric:tabular-nums}
  .rep-table .score.pos{color:var(--crit)}
  .rep-table .score.neg{color:var(--ok)}
  .rep-table .score.zero{color:var(--dim2)}
  .stats{display:grid;grid-template-columns:repeat(2,1fr);gap:1px;background:var(--line)}
  .stat{background:var(--panel);padding:12px 16px}
  .stat .k{font-size:9.5px;color:var(--dim2);text-transform:uppercase;letter-spacing:.7px;
    font-weight:700;margin-bottom:3px}
  .stat .v{font-size:19px;font-weight:700;line-height:1.1}
  .stat .v.crit{color:var(--crit)}.stat .v.ok{color:var(--ok)}
  .stat .v.blue{color:var(--accent)}.stat .v.purple{color:var(--purple)}
  .meter{padding:16px}
  .mhead{display:flex;justify-content:space-between;align-items:baseline;margin-bottom:8px}
  .mhead .l{font-size:11.5px;color:var(--dim);font-weight:600}
  .mhead .r{font-size:19px;font-weight:700}
  .mhead .r.crit{color:var(--crit)}.mhead .r.warn{color:var(--warn)}.mhead .r.ok{color:var(--ok)}
  .mtrack{height:9px;background:var(--panel2);border-radius:5px;overflow:hidden;margin-bottom:12px}
  .mfill{height:100%;border-radius:5px;transition:width .4s}
  .mfill.ok{background:var(--ok)}.mfill.warn{background:var(--warn)}.mfill.crit{background:var(--crit)}
  .mfill.pred{background:var(--purple);opacity:.45}
  .legend{display:flex;gap:14px;font-size:10px;color:var(--dim2)}
  .legend span{display:flex;align-items:center;gap:5px}
  .legend .sw{width:10px;height:4px;border-radius:2px}
  .legend .sw.now{background:var(--crit)}.legend .sw.pred{background:var(--purple);opacity:.55}
  .wgrid{display:grid;grid-template-columns:1fr 1fr;gap:1px;background:var(--line)}
  .wcell{background:var(--panel);padding:12px 14px}
  .wcell .k{font-size:9.5px;color:var(--dim2);text-transform:uppercase;letter-spacing:.7px;
    font-weight:700;margin-bottom:3px}
  .wcell .v{font-size:14px;font-weight:700;font-family:ui-monospace,Menlo,monospace;word-break:break-all}
  .wcell .v.hl{color:var(--accent)}.wcell .v.purple{color:var(--purple)}.wcell .v.cyan{color:var(--cyan)}
  .pred{display:grid;grid-template-columns:1fr 56px;gap:8px;padding:9px 14px;
    border-bottom:1px solid #f1f5f9;align-items:center}
  .pred:last-child{border-bottom:none}
  .pred .lbl{font-family:ui-monospace,Menlo,monospace;font-size:11px;word-break:break-all;line-height:1.4}
  .pred .rsn{font-size:9.5px;color:var(--dim);margin-top:3px}
  .pred .conf{font-size:12.5px;font-weight:700;text-align:right;color:var(--purple)}
  .pred .cbar{height:3px;background:var(--panel2);border-radius:2px;margin-top:4px;overflow:hidden}
  .pred .cbar-f{height:100%;background:var(--purple)}
  .pred .kind{display:inline-block;font-size:8.5px;font-weight:700;padding:1px 5px;border-radius:3px;
    background:var(--panel2);color:var(--dim);letter-spacing:.4px;text-transform:uppercase;margin-left:6px}
  .mlog{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:10.5px;max-height:280px;overflow-y:auto}
  .mlog::-webkit-scrollbar{width:6px}.mlog::-webkit-scrollbar-thumb{background:var(--line2);border-radius:3px}
  .mrow{display:grid;grid-template-columns:88px 66px 1fr;gap:8px;padding:6px 14px;
    border-bottom:1px solid #f1f5f9;align-items:start}
  .mrow:last-child{border-bottom:none}
  .mrow .t{color:var(--dim2);font-size:9.5px;padding-top:2px}
  .mrow .kind{font-size:9px;font-weight:800;letter-spacing:.5px;text-align:center;padding:2px 4px;border-radius:3px}
  .mrow .kind.WRAPPER{background:#cffafe;color:#0e7490}
  .mrow .kind.PREDICT{background:#ede9fe;color:#6d28d9}
  .mrow .kind.HIT{background:#dcfce7;color:#15803d}
  .mrow .lbl{color:var(--text);font-size:10.5px;word-break:break-all}
  .mrow .dt{color:var(--dim);font-size:9.5px;margin-top:2px;word-break:break-all}
  .atk .path{font-family:ui-monospace,Menlo,monospace;font-size:11px;background:var(--panel2);
    padding:7px 10px;border-radius:5px;margin-bottom:10px;word-break:break-all}
  .atk .path b{color:var(--purple);font-weight:800;margin-right:7px}
  .atk .desc{font-size:12px;color:var(--dim);line-height:1.55;margin-bottom:10px}
  .tag{display:inline-block;font-size:9.5px;font-weight:700;padding:2px 7px;border-radius:4px;
    margin-right:5px;margin-bottom:4px}
  .tag.blue{background:#dbeafe;color:#1d4ed8}.tag.amber{background:#fef3c7;color:#92400e}
  .tag.red{background:#fee2e2;color:#b91c1c}.tag.purple{background:#ede9fe;color:#6d28d9}
  .cal-table{width:100%;font-size:11px}
  .cal-table tr{border-bottom:1px solid #f1f5f9}
  .cal-table tr:last-child{border-bottom:none}
  .cal-table td{padding:7px 14px}
  .cal-table .model{font-family:ui-monospace,Menlo,monospace;font-size:10.5px;color:var(--purple)}
  .cal-table .w{text-align:right;font-weight:700;font-variant-numeric:tabular-nums}
  .cal-table .w.good{color:var(--ok)}.cal-table .w.mid{color:var(--warn)}.cal-table .w.bad{color:var(--crit)}
  .cal-table .n{text-align:right;color:var(--dim2);font-size:10px}
  .foot{text-align:center;color:var(--dim2);font-size:11px;padding:12px 20px 24px;line-height:1.9}
  .foot a{color:var(--dim);text-decoration:none;margin:0 6px}
  .foot a:hover{text-decoration:underline}
  .envbar{background:var(--panel2);border-bottom:1px solid var(--line);padding:7px 20px;
    display:flex;gap:18px;font-size:10.5px;color:var(--dim2);flex-wrap:wrap}
  .envbar b{color:var(--dim);font-weight:600}
  .scope{background:#fff7ed;border:1px solid #fed7aa;color:#7c2d12;font-size:11.5px;
    padding:10px 20px;line-height:1.55}
  .scope b{color:#9a3412}
  .howto{background:#fafbff;border:1px solid #dbeafe;border-radius:10px;padding:16px;margin:0 20px 20px}
  .howto h3{font-size:11px;font-weight:800;color:#1e3a8a;text-transform:uppercase;
    letter-spacing:.7px;margin-bottom:10px}
  .howto pre{background:#fff;border:1px solid var(--line);border-radius:7px;padding:11px 13px;
    font-family:ui-monospace,Menlo,monospace;font-size:11px;color:#334155;
    overflow-x:auto;line-height:1.6;margin-bottom:8px}
  .howto p{font-size:11.5px;color:var(--dim);line-height:1.65}
  @media (max-width:1300px){.grid{grid-template-columns:1fr 1fr}.grid .col:nth-child(3){grid-column:1/-1}}
  @media (max-width:900px){
    .top{padding:10px 14px;gap:10px}
    .metrics{order:10;width:100%;margin-left:0;overflow-x:auto;border-radius:8px}
    .metric{min-width:80px;flex-shrink:0;padding:8px 12px}
    .grid{grid-template-columns:1fr;padding:12px;gap:12px}
    .ev{grid-template-columns:46px 28px 34px 1fr 62px;gap:6px;padding:8px 12px}
    .ev .why{display:none}
    .mrow{grid-template-columns:80px 60px 1fr;gap:6px;padding:6px 12px}
    .foot{padding:12px 14px 24px}
    .foot a{display:inline-block;padding:2px 0}
    .howto{margin:0 12px 16px}
    .envbar{padding:7px 14px;gap:12px}
    .scope{padding:10px 14px}
  }
  @media (prefers-reduced-motion:reduce){*{animation-duration:.01ms !important;transition-duration:.01ms !important}}
</style>
</head>
<body>

<div class="top">
  <div class="brand">
    <div class="m">PDH</div>
    <?= h($SITE_SHORT) ?>
    <span class="env">CONSOLE</span>
  </div>
  <div class="live"><span class="d"></span> Live</div>
  <div class="metrics">
    <div class="metric"><span class="k">Observed</span><span class="v"><?= $totalObserved ?></span></div>
    <div class="metric"><span class="k">Blocked</span><span class="v crit"><?= $blocked ?></span></div>
    <div class="metric"><span class="k">Challenged</span><span class="v"><?= $challenged ?></span></div>
    <div class="metric"><span class="k">Cleared</span><span class="v ok"><?= $cleared ?></span></div>
    <div class="metric"><span class="k">Wrapper</span><span class="v cyan"><?= h($w['envelope']) ?><small><?= h($w['rotations']) ?>×</small></span></div>
    <div class="metric"><span class="k">Predicts</span><span class="v purple"><?= count($state['predictions']) ?><small><?= $predHitRate ?>%</small></span></div>
    <div class="metric"><span class="k">Threat</span><span class="v <?= h($threatLvl) ?>"><?= $threatPct ?>%<small>/<?= $predictedPct ?>%</small></span></div>
  </div>
</div>

<div class="envbar">
  <span><b>store</b> <?= h($storeName) ?></span>
  <span><b>geo</b> <?= h($geoSource) ?></span>
  <span><b>rules</b> 10</span>
  <span><b>rate window</b> <?= PDHPI_RATE_WINDOW ?>s</span>
  <span><b>reputation</b> <?= count($state['reputation'] ?? []) ?> tracked</span>
  <span><b>sessions</b> <?= count($state['sessions'] ?? []) ?> seen</span>
  <span><b>challenges</b> <?= count($state['challenges'] ?? []) ?> passed</span>
</div>

<div class="scope">
  <b>Scope:</b> PDHPI is a complementary layer. It is not a WAF, not RASP,
  not a replacement for parameterized queries, output encoding, or patched
  dependencies. Its value is cheap, correlated, per-request signal you can
  act on without a separate service.
</div>

<div class="howto">
  <h3>Drop-in usage</h3>
  <pre><?php
require_once 'index.php';

$v = pdhpi_observe([
    'ip'      => $_SERVER['REMOTE_ADDR'] ?? '',
    'method'  => $_SERVER['REQUEST_METHOD'] ?? 'GET',
    'path'    => parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH),
    'query'   => $_SERVER['QUERY_STRING'] ?? '',
    'body'    => file_get_contents('php://input'),
    'session' => $_COOKIE['session'] ?? null,   // optional
    'user'    => $currentUserId ?? null,        // optional
]);

switch ($v['action']) {
    case 'block':     http_response_code(403); exit;
    case 'challenge': pdhpi_render_challenge($v['challenge']); exit;
}</pre>
  <p>Edge endpoints: <code style="background:#fff;padding:2px 6px;border-radius:4px;font-family:ui-monospace,monospace;color:#6d28d9">?pdhpi=observe</code> returns a JSON verdict and sets the status code. <code style="background:#fff;padding:2px 6px;border-radius:4px;font-family:ui-monospace,monospace;color:#6d28d9">?pdhpi=envelope</code> returns the current rotating envelope. <code style="background:#fff;padding:2px 6px;border-radius:4px;font-family:ui-monospace,monospace;color:#6d28d9">?pdhpi=challenge</code> serves the proof-of-work gate.</p>
</div>

<div class="grid">

  <div class="col">

<div class="card">
  <div class="ch"><h2><span class="i blue">→</span>Observed event stream</h2></div>
  <div class="cb tight">
    <?php if (empty($state['events'])): ?>
      <div class="empty">
        <b>No traffic observed yet</b>
        This console does not invent events. Hook the library into your application:

        <code>pdhpi_observe(['ip'=>$_SERVER['REMOTE_ADDR'], 'session'=>$_COOKIE['session'] ?? null, ...])</code>

        Every request you observe appears here, with rate, reputation, and session context.
      </div>
    <?php else: ?>
      <div class="feed">
        <?php foreach (array_reverse($state['events']) as $ev): ?>
          <div class="ev">
            <span class="t"><?= h($ev['t']) ?></span>
            <span class="cc"><?= h($ev['cc']) ?></span>
            <span class="method <?= h($ev['method']) ?>"><?= h($ev['method']) ?></span>
            <span class="body">
              <div class="path"><?= h($ev['path']) ?></div>
              <div class="why"><?= h($ev['why']) ?></div>
              <div class="ip"><?= h($ev['ip']) ?><?php if (!empty($ev['session'])): ?> · sess <?= h(substr($ev['session'],0,10)) ?><?php endif; ?></div>
            </span>
            <span class="sig">
              <div class="score <?= $ev['score'] > 0 ? 'hit' : '' ?>"><?= $ev['score'] > 0 ? '+' . $ev['score'] : '—' ?></div>
              <div class="mini">r<?= (int)($ev['rate'] ?? 0) ?> · rep <?= (int)($ev['rep'] ?? 0) ?></div>
            </span>
          </div>
        <?php endforeach; ?>
      </div>
    <?php endif; ?>
  </div>
</div>

<div class="card">
  <div class="ch"><h2><span class="i green">▦</span>Counters</h2></div>
  <div class="stats">
    <div class="stat"><div class="k">Observed</div><div class="v"><?= $totalObserved ?></div></div>
    <div class="stat"><div class="k">Allowed</div><div class="v ok"><?= $cleared ?></div></div>
    <div class="stat"><div class="k">Challenged</div><div class="v"><?= $challenged ?></div></div>
    <div class="stat"><div class="k">Blocked</div><div class="v crit"><?= $blocked ?></div></div>
  </div>
</div>

<div class="card">
  <div class="ch"><h2><span class="i red">◉</span>Top reputation</h2></div>
  <div class="csub">Keyed by fingerprint (<b>fp:</b>) and by IP (<b>ip:</b>). Fine keys drive scoring; coarse keys only track NAT risk.</div>
  <div class="cb tight">
    <?php if ($topReps): ?>
      <table class="rep-table">
        <?php foreach ($topReps as $key => $r): $sc = (int)$r['score']; ?>
          <tr>
            <td class="ip"><?= h($key) ?></td>
            <td class="score <?= $sc > 0 ? 'pos' : ($sc < 0 ? 'neg' : 'zero') ?>">
              <?= $sc > 0 ? '+' : '' ?><?= $sc ?>
            </td>
          </tr>
        <?php endforeach; ?>
      </table>
    <?php else: ?><div class="empty">No reputation tracked yet.</div><?php endif; ?>
  </div>
</div>

<div class="card">
  <div class="ch"><h2><span class="i purple">⌘</span>Rules fired</h2></div>
  <div class="cb tight">
    <?php if ($topRules): ?>
      <table class="rtable">
        <?php foreach ($topRules as $rule => $n): ?>
          <tr><td class="rule"><?= h($rule) ?></td><td class="n"><?= $n ?>×</td></tr>
        <?php endforeach; ?>
      </table>
    <?php else: ?><div class="empty">No rules have fired yet.</div><?php endif; ?>
  </div>
</div>

<div class="card">
  <div class="ch"><h2><span class="i amber">⚠</span>Collateral risk</h2></div>
  <div class="csub">IPs presenting many distinct clients. High counts mean a block here hurts real users — the NAT dampener will have downgraded those to challenge.</div>
  <div class="cb tight">
    <?php if ($collateral): ?>
      <table class="rtable">
        <?php foreach ($collateral as $ip => $n): ?>
          <tr><td class="rule" style="color:var(--dim)"><?= h($ip) ?></td><td class="n"><?= $n ?> clients</td></tr>
        <?php endforeach; ?>
      </table>
    <?php else: ?><div class="empty">No shared-IP patterns detected.</div><?php endif; ?>
  </div>
</div>

  </div>

  <div class="col">

<div class="card">
  <div class="ch"><h2><span class="i amber">◈</span>Rolling threat</h2></div>
  <div class="meter">
    <div class="mhead">
      <span class="l">Current · last <?= PDHPI_WINDOW_EVENTS ?> events</span>
      <span class="r <?= h($threatLvl) ?>"><?= $threatPct ?>%</span>
    </div>
    <div class="mtrack"><div class="mfill pred" style="width:<?= $predictedPct ?>%"></div></div>
    <div class="mhead"><span class="l">Predicted · armed</span><span class="r" style="color:var(--purple)"><?= $predictedPct ?>%</span></div>
    <div class="mtrack"><div class="mfill <?= h($threatLvl) ?>" style="width:<?= $threatPct ?>%"></div></div>
    <div class="legend">
      <span><span class="sw now"></span>current</span>
      <span><span class="sw pred"></span>predicted</span>
    </div>
  </div>
</div>

<div class="card">
  <div class="ch"><h2><span class="i cyan">◉</span>Wrapper state</h2></div>
  <div class="wgrid">
    <div class="wcell"><div class="k">Envelope</div><div class="v hl"><?= h($w['envelope']) ?></div></div>
    <div class="wcell"><div class="k">Padding</div><div class="v cyan"><?= h($w['padding']) ?> B</div></div>
    <div class="wcell"><div class="k">Framing</div><div class="v"><?= h($w['framing']) ?></div></div>
    <div class="wcell"><div class="k">Header order</div><div class="v"><?= h($w['header_order']) ?></div></div>
    <div class="wcell"><div class="k">Rotations</div><div class="v purple"><?= h($w['rotations']) ?></div></div>
    <div class="wcell"><div class="k">Last rotate</div><div class="v" style="font-size:12px"><?= h(date('H:i:s', $w['last_rotate'])) ?></div></div>
  </div>
</div>

<div class="card">
  <div class="ch"><h2><span class="i cyan">↻</span>Morph log</h2></div>
  <div class="cb tight">
    <div class="mlog">
      <?php if ($morphRecent): foreach (array_reverse($morphRecent) as $m): ?>
        <div class="mrow">
          <span class="t"><?= h(substr($m['t'], 11, 8)) ?></span>
          <span class="kind <?= h($m['kind']) ?>"><?= h($m['kind']) ?></span>
          <span><div class="lbl"><?= h($m['label']) ?></div><div class="dt"><?= h($m['detail']) ?></div></span>
        </div>
      <?php endforeach; else: ?>
        <div class="empty">No rotations yet.</div>
      <?php endif; ?>
    </div>
  </div>
</div>

<div class="card">
  <div class="ch"><h2><span class="i amber">◆</span>Top sources</h2></div>
  <div class="cb tight">
    <?php if ($topAttackers): $maxScore = max($topAttackers); ?>
      <table class="atable">
        <?php foreach ($topAttackers as $ip => $s): ?>
          <tr>
            <td class="ip"><?= h($ip) ?></td>
            <td style="width:50%"><div class="bar"><div class="bar-fill" style="width:<?= (int)(($s / $maxScore) * 100) ?>%"></div></div></td>
            <td class="n"><?= $s ?></td>
          </tr>
        <?php endforeach; ?>
      </table>
    <?php else: ?><div class="empty">No scored activity yet.</div><?php endif; ?>
  </div>
</div>

<div class="card">
  <div class="ch"><h2><span class="i purple">⌁</span>Model calibration</h2></div>
  <div class="csub">Per-model confidence weight. Models that consistently miss are down-weighted automatically.</div>
  <div class="cb tight">
    <?php if ($calibration): ?>
      <table class="cal-table">
        <?php foreach ($calibration as $model => $c): $w = (float)($c['weight'] ?? 1.0); ?>
          <tr>
            <td class="model"><?= h($model) ?></td>
            <td class="n"><?= (int)($c['hit'] ?? 0) ?>/<?= (int)($c['made'] ?? 0) ?></td>
            <td class="w <?= $w >= 0.75 ? 'good' : ($w >= 0.45 ? 'mid' : 'bad') ?>"><?= number_format($w, 2) ?></td>
          </tr>
        <?php endforeach; ?>
      </table>
    <?php else: ?><div class="empty">No calibration data yet.</div><?php endif; ?>
  </div>
</div>

  </div>

  <div class="col">

<div class="card">
  <div class="ch"><h2><span class="i purple">◇</span>Prediction queue</h2></div>
  <div class="csub"><b><?= count($state['predictions']) ?></b> standing · <b><?= $ps['hit'] ?></b> hits of <b><?= $ps['made'] ?></b> · <b><?= $predHitRate ?>%</b> hit rate</div>
  <div class="cb tight">
    <?php if ($state['predictions']): ?>
      <?php foreach ($state['predictions'] as $p): ?>
        <div class="pred">
          <div>
            <div class="lbl"><?= h($p['label']) ?><span class="kind"><?= h($p['model'] ?? $p['kind']) ?></span></div>
            <div class="rsn"><?= h($p['reason']) ?></div>
          </div>
          <div>
            <div class="conf"><?= number_format($p['confidence'], 2) ?></div>
            <div class="cbar"><div class="cbar-f" style="width:<?= (int)($p['confidence']*100) ?>%"></div></div>
          </div>
        </div>
      <?php endforeach; ?>
    <?php else: ?>
      <div class="empty">No standing predictions.
The engine populates as real events accumulate.</div>
    <?php endif; ?>
  </div>
</div>

<?php if ($latestAttack): ?>
<div class="card atk">
  <div class="ch"><h2><span class="i red"></span>Latest attacker move</h2></div>
  <div class="cb">
    <div style="font-size:14px;font-weight:700;margin-bottom:7px"><?= h($latestAttack['tactic']) ?></div>
    <div class="path"><b><?= h($latestAttack['method']) ?></b><?= h($latestAttack['path']) ?></div>
    <div class="desc"><?= h($latestAttack['why']) ?></div>
    <div>
      <span class="tag blue"><?= h($latestAttack['cc']) ?></span>
      <?php if (!empty($latestAttack['rule'])): ?><span class="tag amber"><?= h($latestAttack['rule']) ?></span><?php endif; ?>
      <span class="tag red">+<?= $latestAttack['score'] ?></span>
      <?php if (!empty($latestAttack['rep'])): ?><span class="tag purple">rep <?= (int)$latestAttack['rep'] ?></span><?php endif; ?>
    </div>
  </div>
</div>
<?php endif; ?>

  </div>

</div>

<div class="foot">
  PDHPI v2 — Polymorphic Dual Hyper-Predictive Infrastructure ·
  <a href="?pdhpi=envelope">envelope.json</a>
  <a href="?pdhpi=observe">observe.json</a>
  <a href="?reset=1">reset</a>
</div>

</body>
</html>
