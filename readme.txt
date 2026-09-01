=== Ironhide ===
Contributors: optimus
Tags: security, admin, ip, allowlist, firewall
Requires at least: 5.8
Requires PHP: 7.4
Stable tag: 1.0.0
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Restrict the WordPress admin area to an allowlist of IP addresses, CIDR ranges and IPv4 wildcards — with a monitor mode and built-in lockout recovery.

== Description ==

Ironhide gates `wp-admin` so that only the IP addresses you allow can reach it —
independent of login cookies, so a stolen session is still refused from a foreign
address.

Its scope is wp-admin and nothing else. The login page, the REST API and XML-RPC
are deliberately left alone: `wp-login.php` is used by customers and members, not
just staff, and gating it locks them all out. Restrict those at the web server,
CDN or WAF layer, where per-route rules belong.

It is designed around a "never lock yourself out" rule:

* Monitor mode: see exactly what *would* be blocked, while blocking nothing.
* Fail-open: nothing is blocked until you pick a mode *and* add an IP.
* Your current IP is auto-added to the allowlist on every settings save.
* Emergency off switch: `define( 'IRONHIDE_DISABLE', true );` or a marker file.
* URL bypass key: `define( 'IRONHIDE_BYPASS_KEY', 'secret' );` + a query arg.
* WP-CLI recovery: `wp ironhide off`, `wp ironhide allow <ip>`, `wp ironhide status`.

Entries may be single IPs (`203.0.113.10`), CIDR ranges (`203.0.113.0/24`,
`2001:db8::/48`) or IPv4 wildcards (`192.168.1.*`). Forwarding headers
(`X-Forwarded-For` / `X-Real-IP`) are only trusted when the immediate peer is a
listed proxy, so the allowlist cannot be defeated by a spoofed header.

This is a prototype. Also restrict `wp-admin/` at the web server / CDN layer for
defence in depth; see the bundled README.md.

== Installation ==

1. Upload the `ironhide` folder to `/wp-content/plugins/`.
2. Activate through the Plugins screen.
3. Go to Settings → Ironhide, add your IP(s), and set the mode to **Monitor**.
4. Leave it a day, then check "Recent activity" to confirm nothing legitimate
   would have been blocked.
5. Read the "Recovery" section on the settings page, then switch to **Enforce**.

== Frequently Asked Questions ==

= What happens if I lock myself out? =

Use any one of the recovery paths: the `IRONHIDE_DISABLE` constant, the
`wp-content/ironhide-emergency-disable` marker file, the `IRONHIDE_BYPASS_KEY`
URL key, or `wp ironhide off` from the shell.

= Does it block the login page? =

No, and that is deliberate. `wp-login.php` is not part of wp-admin and is used by
customers and members as well as staff. Someone with valid credentials can still
sign in from anywhere — they just hit a 403 the moment they try to use the
dashboard.

= Can anyone see my allowlist? =

No. It is never sent to the REST API (`show_in_rest` is explicitly off), it is
not autoloaded onto front-end requests, it is not handed to filter callbacks,
and the 403 page a blocked visitor sees names no address at all — not even their
own. Only a user with `manage_options` can read it, on the settings screen or via
`wp ironhide list`. The block log lives under a salt-derived filename so it
cannot be fetched by guessing its URL, and uninstall removes it.

= Does it protect the REST API or XML-RPC? =

No. Protect those at the web server or WAF layer.

= Will it break my frontend contact form? =

No. `admin-ajax.php` and `admin-post.php` default to gating logged-in requests
only, so anonymous frontend traffic keeps working. If a frontend feature calls
admin-ajax while the visitor is logged in, monitor mode will show you before you
enforce anything.

== Changelog ==

= 1.0.0 =
* IP/CIDR/wildcard allowlist for wp-admin, with off/monitor/enforce modes.
* Per-policy handling of admin-ajax.php and admin-post.php.
* Fail-open behaviour, emergency disable, URL bypass key, WP-CLI commands.
* Block logging with rotation, plus a recent-activity view on the settings page.
