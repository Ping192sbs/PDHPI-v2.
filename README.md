
# PDHPI

**Polymorphic Dual Hyper-Predictive Infrastructure**

A single-file portable defense layer for PHP.  
Library + operator console. No Composer. No database required.

Created by [Ping192](https://ping192.sbs)

## What it is

PDHPI observes real inbound requests, scores them, tracks rate / reputation / session state, can issue a proof-of-work challenge, rotates a transport envelope, and runs calibrated attack predictions.

It is a **complementary** layer — not a WAF, not RASP, and not a replacement for secure coding.

## Requirements

- PHP 7.4+
- Write access to `./storage/`
- Optional: Redis, MaxMind GeoLite2

## Quick start

### As a library

```php
require_once 'index.php';

$v = pdhpi_observe([
    'ip'      => $_SERVER['REMOTE_ADDR'] ?? '',
    'method'  => $_SERVER['REQUEST_METHOD'] ?? 'GET',
    'path'    => parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH),
    'query'   => $_SERVER['QUERY_STRING'] ?? '',
    'body'    => file_get_contents('php://input'),
    'session' => $_COOKIE['session'] ?? null,
]);

switch ($v['action']) {
    case 'block':
        http_response_code(403);
        exit;
    case 'challenge':
        pdhpi_render_challenge($v['challenge']);
        exit;
}
