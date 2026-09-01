# Ironhide

A WordPress plugin that restricts the **admin area** (`wp-admin`) to an allowlist
of IP addresses, CIDR ranges and IPv4 wildcards — built so it is hard to lock
yourself out.

This is a **prototype**: production-shaped code and a standalone test harness,
but it has not been run against a live WordPress install. See
"Scope & limitations" and "Verification status".

> **Before installing:** the containing folder is still named `admin-ip-guard`.
> Rename it to `ironhide` so the plugin slug matches the main file
> (`ironhide/ironhide.php`). WordPress will run it either way, but every tool
> that keys off the slug expects them to agree.

---

## Scope: wp-admin and nothing else

| Surface | Gated? |
|---|---|
| `wp-admin/*` (dashboard, network admin, user admin) | **Yes** |
| `admin-ajax.php` / `admin-post.php` | Per policy — see below |
| `wp-login.php` | **No** |
| REST API (`/wp-json/`) | **No** |
| XML-RPC (`xmlrpc.php`) | **No** |
| Static files, `load-scripts.php`, `load-styles.php` | **No** |

The gate is independent of authentication: a stolen or legitimately obtained
login cookie still cannot reach the dashboard from a non-allowlisted address.

### Why the login page is deliberately not gated

`wp-login.php` is not part of wp-admin, and it is not only used by staff. On a
membership, LMS or WooCommerce site, gating it locks out every customer, not just
administrators. Ironhide therefore leaves authentication alone and gates the
thing it is named for. Restrict or rate-limit `wp-login.php` at the web server,
CDN or WAF layer, where per-route rules belong.

The practical consequence: an attacker with valid credentials can still log in
from anywhere. They land on a 403 the moment they try to use the dashboard, and
(under the default AJAX policy) cannot drive the site through `admin-ajax.php`
either.

### Why the gate runs on `init`

`wp-admin/admin.php` defines `WP_ADMIN` *before* it loads `wp-load.php`, so
`is_admin()` is already `true` by the time `init` fires. Priority 1 on `init` is
the earliest point at which a plugin can act with `$pagenow`, request slashing
(`wp_magic_quotes()`) and the current user all in their documented state. This
was checked against core `wp-settings.php`, `wp-includes/vars.php`,
`wp-admin/admin.php`, `admin-ajax.php` and `admin-post.php`.

### `admin-ajax.php` / `admin-post.php`

These two live in wp-admin but serve the public site, so they get their own
policy:

| Policy | Behaviour |
|---|---|
| `public_only` (**default**) | Anonymous requests pass; authenticated requests are gated. |
| `open` | Never gated. |
| `gated` | Always gated. |

`public_only` is the useful default: public contact forms, search-as-you-type and
payment callbacks are all logged-out traffic and keep working, while an
authenticated session from an unapproved address gets the same 403 as the
dashboard. Switch to `open` if you have frontend features that call
`admin-ajax.php` *while logged in* — run monitor mode first and the log will tell
you whether you do.

---

## Anti-lockout design (the important part)

### 1. Monitor mode
Set the mode to **Monitor** and Ironhide blocks nothing at all — it just records
every request that *would* have been refused, to the log and to the "Recent
activity" table on the settings screen. Run it for a day, confirm the only
entries are strangers, then switch to Enforce. This is the recommended path and
it is what protects you from the realistic failure: a dynamic IP that rotates
three days after you configured the allowlist.

### 2. Fail-open by default
- The mode defaults to **off**.
- Whatever the mode, an **empty allowlist blocks nobody**.
- CLI, cron, and the WordPress install/upgrade screens are never gated.

### 3. You cannot lock yourself out on save
`Ironhide_Settings::sanitize_settings()` resolves the exact IP the guard would
evaluate for the current visitor (the same `Ironhide_Core::get_effective_ip()`
code path) and appends it to the allowlist on every save. If your IP cannot be
determined at all, the mode is forced back to off rather than enforcing a rule
that would refuse everyone.

### 4. Emergency disable — two forms
- Constant, in `wp-config.php`:
  ```php
  define( 'IRONHIDE_DISABLE', true );
  ```
- Marker file (via FTP/SSH/file manager — works even when you cannot reach the
  admin at all):
  ```
  wp-content/ironhide-emergency-disable
  ```
  An empty file is enough; its presence bypasses the gate.

### 5. URL bypass key (no file access needed)
Define a secret in `wp-config.php`:
```php
define( 'IRONHIDE_BYPASS_KEY', 'replace-with-a-long-random-secret' );
```
Then visit:
```
/wp-admin/?ironhide_bypass=replace-with-a-long-random-secret
```
Use only URL-safe characters (letters, digits, `-`, `_`). The key is compared in
constant time (`hash_equals`), and a short-lived (15-minute), HMAC-signed cookie
is dropped so subsequent admin navigation also passes while you fix the
allowlist. The cookie is only accepted when a bypass key has been configured, and
its signature derives from `wp_salt('auth')` rather than the raw `AUTH_SALT`
constant, so a missing or placeholder salt cannot be turned into a forgeable
cookie.

Note that the key will appear in your web server's access log. Rotate it after
use, and prefer the marker file if you have filesystem access.

### 6. WP-CLI (shell access)
CLI requests are never gated, so these always work:
```bash
wp ironhide status
wp ironhide allow 203.0.113.10
wp ironhide allow 203.0.113.0/24
wp ironhide remove 203.0.113.10
wp ironhide list
wp ironhide monitor          # observe without blocking
wp ironhide enforce
wp ironhide off              # disarm, allowlist preserved
wp ironhide log --limit=50
```

---

## Configuration

**Settings → Ironhide.**

- **Protection** — Off / Monitor / Enforce.
- **Allowed IP addresses** — one per line: `203.0.113.10`, `203.0.113.0/24`,
  `2001:db8::/48`, or IPv4 wildcard `192.168.1.*`. Your current IP is added
  automatically on save. An entry that matches everything (`0.0.0.0/0`, `::/0`,
  `*.*.*.*`) is accepted but warned about, because it silently disables
  protection.
- **Forwarding headers** — only enable behind a reverse proxy/CDN.
- **Trusted proxies** — the proxy/CDN addresses whose headers may be trusted.
- **admin-ajax / admin-post** — the policy described above.
- **Logging** — record blocks and would-be blocks. Monitor mode needs this on.

### Trusted-proxy behaviour (anti-spoofing)
`REMOTE_ADDR` is the only value that cannot be forged. `X-Forwarded-For` and
`X-Real-IP` are consulted **only** when `REMOTE_ADDR` is itself in the trusted
proxy list. `X-Forwarded-For` is then walked right-to-left, returning the first
non-proxy address — the real client as seen by the first trusted proxy. If the
site is not behind a proxy, leave header-trusting **off**; the settings screen
warns if you trust headers without listing the peer.

---

## Logging

Records go to a salt-derived filename inside:
```
wp-content/uploads/ironhide/blocked-<16-hex>.log
```
The random-looking component is derived from `wp_salt('auth')`, so it is stable
for your site but cannot be guessed from outside. Uploads is web-readable by
default and nginx ignores `.htaccess`, so this is what actually keeps the log
private there; the server rules below are defence in depth rather than the only
defence. Rotating your salts changes the name — the old file is orphaned and
swept on uninstall, and logging continues in a fresh one.

Tab-separated, one record per line:
`time, event, ip, remote_addr, where, user, bypass, uri, ua`

`event` is `block` (refused) or `would_block` (monitor mode). The file rotates to
`blocked.log.1` at 1 MiB. Fields are stripped of every control character — which
includes TAB, CR and LF, so a hostile User-Agent cannot forge a column or a
record — and capped at 200 characters. The `ironhide_bypass` query value is
redacted, so the recovery key is never written to disk.

The directory gets an `index.php`, an `.htaccess` (Apache) and a `web.config`
(IIS), recreated on every write if deleted. **nginx honours none of these**, so
add the equivalent yourself:
```nginx
location ^~ /wp-content/uploads/ironhide/ { deny all; }
```

---

## Hooks

```php
// Override the allow/deny decision.
// The settings array is deliberately not passed — see "What is never exposed".
add_filter( 'ironhide_request_is_allowed', function ( $allowed, $where ) {
	return $allowed;
}, 10, 2 );

// Change what a blocked visitor sees. Whatever you return is served to an
// unauthenticated stranger.
add_filter( 'ironhide_deny_message', function ( $message, $where ) {
	return $message;
}, 10, 2 );
```

---

## What is never exposed

The allowlist is the map of who can reach your admin area. Ironhide treats it as
a secret, and the rules below are enforced in code, not just by convention.

**The 403 page says only "You do not have permission to access this area."** It
names no allowlist entry — and it does not echo the visitor's own detected IP
either. Under a proxy configuration, echoing the *effective* IP would tell an
attacker which header the guard actually evaluated, which is the first thing you
need in order to probe the list by spoofing. Operators read the detected IP from
the log instead, which never leaves the server. Two tests assert the 403 body
contains neither.

**The option is never exposed over REST.** `register_setting()` passes
`'show_in_rest' => false` explicitly rather than relying on the default, so
`/wp-json/wp/v2/settings` cannot be made to publish it by accident.

**The option is not autoloaded.** It is created on activation with autoload off,
so the allowlist is not loaded into the `alloptions` blob on every front-end
request — only where it is actually needed, inside wp-admin.

**Filters are not handed the list.** `ironhide_request_is_allowed` receives the
decision and the script name, not the settings array. A callback that genuinely
needs the allowlist can ask for it deliberately via
`Ironhide_Guard::get_settings()`.

**Admin notices are capability-gated.** A notice can name the address that was
auto-added on save, so `render_notices()` checks `manage_options` rather than
printing to whoever loads an admin page. The allow-everything warning reports a
*count*, not the matching entries, so allowlist content is never copied into a
transient.

**`wp ironhide status` prints counts, not entries.** Only the explicit
`wp ironhide list` prints the allowlist itself.

**Uninstall removes the traces.** The option, the log (including orphans left by
a salt rotation), and any queued notice transients are all deleted.

The one thing Ironhide cannot hide is whether *your own* address is allowed: a
403 versus a dashboard is the observable behaviour, and that is inherent to the
control. What stops that from becoming an oracle for the whole list is the
trusted-proxy design — a client cannot make the guard evaluate an address other
than its own unless you have enabled header trust without listing your proxy,
which the settings screen warns about on save.

---

## Verification status

**Not verified.** This revision has not been syntax-checked or test-run: no PHP
binary is available in the environment it was written in. Before installing it
anywhere, run:

```bash
find . -name '*.php' -exec php -l {} \;
```

```bash
php tests/test-core.php && php tests/test-guard.php
```

The two harnesses need no WordPress install:

- `tests/test-core.php` — IP/CIDR/wildcard matching, entry sanitisation,
  allow-everything detection, and malformed-input hardening.
- `tests/test-guard.php` — fail-open, monitor mode, the wp-admin-only scope, the
  three AJAX policies, bypass key and cookie, trusted-proxy handling, settings
  anti-lockout and key whitelisting, and the log round-trip.

Also unverified, and needing a live site: the `init` gate firing against real
WordPress, and the settings round-trip through the options API.

---

## Scope & limitations (be honest with yourself)

- **Not a network perimeter.** A plugin can only act once WordPress boots. For a
  real deployment, also restrict `wp-admin/` at the web server / CDN / WAF layer
  (nginx `allow`/`deny`, `.htaccess`, Cloudflare firewall rules). Ironhide is the
  in-application second layer.
- **Login, REST and XML-RPC are out of scope** by design. If you need those
  locked down, that is a different control at a different layer.
- **Multisite:** settings are per-site, and the options page appears under each
  site's Settings menu. Network admin screens (`/wp-admin/network/`) are gated by
  the current site's allowlist. There is no network-wide settings screen.
- **IPv6 zone ids** are stripped; IPv4-mapped IPv6 is normalised to IPv4.
- **Wildcards are IPv4-only.** Use CIDR for IPv6.
- **The bypass cookie** relies on the site salts; keep them secret, as always.

---

## File layout

```
ironhide/
├── ironhide.php                       bootstrap + plugin header
├── uninstall.php                      removes option + log directory on deletion
├── readme.txt                         WordPress.org-style readme
├── README.md                          this file
├── includes/
│   ├── class-ironhide-core.php        IP parse/match/detect (no WP dependencies)
│   ├── class-ironhide-recovery.php    disable constant, marker file, bypass key/cookie
│   ├── class-ironhide-logger.php      block log, rotation, tail reader
│   ├── class-ironhide-guard.php       enforcement (init, wp-admin only)
│   ├── class-ironhide-settings.php    options page + anti-lockout sanitise
│   └── class-ironhide-cli.php         WP-CLI commands
└── tests/
    ├── test-core.php                  matcher tests
    └── test-guard.php                 enforcement / recovery / settings tests
```
