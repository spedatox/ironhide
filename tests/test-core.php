<?php
/**
 * Isolated unit tests for Ironhide_Core (no WordPress required).
 *
 * Run with:
 *   php tests/test-core.php
 *
 * Exits non-zero on any failure.
 *
 * @package Ironhide
 */

if ( PHP_SAPI !== 'cli' ) {
	fwrite( STDERR, "CLI only.\n" );
	exit( 2 );
}

// The core matcher has no WordPress dependencies, but the file still guards
// against direct web access via ABSPATH.
define( 'ABSPATH', __DIR__ . '/../../' );
require_once __DIR__ . '/../includes/class-ironhide-core.php';

$failures = 0;
$count    = 0;

/**
 * Assert two values are strictly equal.
 *
 * @param mixed  $expected Expected value.
 * @param mixed  $actual   Actual value.
 * @param string $label    Test description.
 * @return void
 */
function ih_assert( $expected, $actual, $label ) {
	global $failures, $count;
	$count++;
	if ( $expected === $actual ) {
		fwrite( STDOUT, "ok   - $label\n" );
		return;
	}
	$failures++;
	fwrite(
		STDOUT,
		"FAIL - $label\n       expected: " . var_export( $expected, true ) .
		"\n       actual:   " . var_export( $actual, true ) . "\n"
	);
}

// --- normalize_ip ---------------------------------------------------------
ih_assert( '203.0.113.10', Ironhide_Core::normalize_ip( '203.0.113.10' ), 'normalize: plain IPv4 passes through' );
ih_assert( '2001:db8::1', Ironhide_Core::normalize_ip( '2001:DB8::1' ), 'normalize: IPv6 lowercased' );
ih_assert( '2001:db8::1', Ironhide_Core::normalize_ip( '2001:db8::1%eth0' ), 'normalize: IPv6 zone id stripped' );
ih_assert( '203.0.113.10', Ironhide_Core::normalize_ip( '::ffff:203.0.113.10' ), 'normalize: IPv4-mapped IPv6 -> IPv4' );
ih_assert( '', Ironhide_Core::normalize_ip( 'not-an-ip' ), 'normalize: invalid returns empty' );
ih_assert( '', Ironhide_Core::normalize_ip( array( '1.2.3.4' ) ), 'normalize: array input returns empty (no TypeError)' );
ih_assert( '', Ironhide_Core::normalize_ip( null ), 'normalize: null returns empty' );

// --- exact match ----------------------------------------------------------
ih_assert( true, Ironhide_Core::ip_matches_entry( '203.0.113.10', '203.0.113.10' ), 'exact IPv4 match' );
ih_assert( false, Ironhide_Core::ip_matches_entry( '203.0.113.11', '203.0.113.10' ), 'exact IPv4 non-match' );
ih_assert( true, Ironhide_Core::ip_matches_entry( '2001:db8::1', '2001:db8::1' ), 'exact IPv6 match' );
ih_assert( true, Ironhide_Core::ip_matches_entry( '203.0.113.10', '::ffff:203.0.113.10' ), 'exact: v4 matches mapped-v6 entry' );
ih_assert( false, Ironhide_Core::ip_matches_entry( 'garbage', 'more-garbage' ), 'exact: two invalid values never match each other' );
ih_assert( false, Ironhide_Core::ip_matches_entry( '203.0.113.10', array( 'x' ) ), 'exact: non-scalar entry rejected' );

// --- CIDR IPv4 ------------------------------------------------------------
ih_assert( true, Ironhide_Core::cidr_match( '203.0.113.42', '203.0.113.0/24' ), 'CIDR v4 inside /24' );
ih_assert( false, Ironhide_Core::cidr_match( '203.0.114.1', '203.0.113.0/24' ), 'CIDR v4 outside /24' );
ih_assert( true, Ironhide_Core::cidr_match( '203.0.113.0', '203.0.113.0/32' ), 'CIDR /32 exact' );
ih_assert( false, Ironhide_Core::cidr_match( '203.0.113.1', '203.0.113.0/32' ), 'CIDR /32 non-match' );
ih_assert( true, Ironhide_Core::cidr_match( '10.1.2.3', '10.0.0.0/8' ), 'CIDR /8 broad' );

// A malformed prefix must never be cast to /0 (which would match everything).
ih_assert( false, Ironhide_Core::cidr_match( '6.6.6.6', '203.0.113.0/' ), 'CIDR: empty prefix does not become /0' );
ih_assert( false, Ironhide_Core::cidr_match( '6.6.6.6', '203.0.113.0/abc' ), 'CIDR: non-numeric prefix does not become /0' );
ih_assert( false, Ironhide_Core::cidr_match( '6.6.6.6', '203.0.113.0/-1' ), 'CIDR: negative prefix rejected' );
ih_assert( false, Ironhide_Core::cidr_match( '2001:db8::1', '203.0.113.0/24' ), 'CIDR: v6 address against v4 range' );

// --- CIDR IPv6 ------------------------------------------------------------
ih_assert( true, Ironhide_Core::cidr_match( '2001:db8::1', '2001:db8::/32' ), 'CIDR v6 inside /32' );
ih_assert( false, Ironhide_Core::cidr_match( '2001:db9::1', '2001:db8::/32' ), 'CIDR v6 outside /32' );
ih_assert( true, Ironhide_Core::cidr_match( 'fe80::1', 'fe80::/10' ), 'CIDR v6 link-local /10' );

// --- wildcard -------------------------------------------------------------
ih_assert( true, Ironhide_Core::wildcard_match( '192.168.1.42', '192.168.1.*' ), 'wildcard last octet' );
ih_assert( false, Ironhide_Core::wildcard_match( '192.168.2.42', '192.168.1.*' ), 'wildcard last octet non-match' );
ih_assert( true, Ironhide_Core::wildcard_match( '10.0.0.7', '*.*.*.*' ), 'wildcard all octets' );
ih_assert( true, Ironhide_Core::ip_matches_entry( '192.168.1.42', '192.168.1.*' ), 'ip_matches_entry routes to wildcard' );
ih_assert( false, Ironhide_Core::wildcard_match( '2001:db8::1', '192.168.1.*' ), 'wildcard: IPv6 never matches a v4 pattern' );

// --- ip_in_list -----------------------------------------------------------
$list = array( '203.0.113.0/24', '2001:db8::/32', '192.168.1.*', '198.51.100.7' );
ih_assert( true, Ironhide_Core::ip_in_list( '203.0.113.9', $list ), 'ip_in_list CIDR hit' );
ih_assert( true, Ironhide_Core::ip_in_list( '192.168.1.99', $list ), 'ip_in_list wildcard hit' );
ih_assert( true, Ironhide_Core::ip_in_list( '198.51.100.7', $list ), 'ip_in_list exact hit' );
ih_assert( false, Ironhide_Core::ip_in_list( '198.51.100.8', $list ), 'ip_in_list miss' );
ih_assert( false, Ironhide_Core::ip_in_list( '', $list ), 'ip_in_list: empty IP never matches' );
ih_assert( false, Ironhide_Core::ip_in_list( '198.51.100.7', 'not-a-list' ), 'ip_in_list: non-array list returns false' );

// --- sanitize_ip_entry ----------------------------------------------------
ih_assert( '203.0.113.10', Ironhide_Core::sanitize_ip_entry( '203.0.113.10' ), 'sanitize: exact IPv4 kept' );
ih_assert( '203.0.113.0/24', Ironhide_Core::sanitize_ip_entry( '203.0.113.0/24' ), 'sanitize: CIDR normalised' );
ih_assert( '2001:db8::/32', Ironhide_Core::sanitize_ip_entry( '2001:db8::/32' ), 'sanitize: IPv6 CIDR normalised' );
ih_assert( '192.168.1.*', Ironhide_Core::sanitize_ip_entry( '192.168.1.*' ), 'sanitize: wildcard normalised' );
ih_assert( false, Ironhide_Core::sanitize_ip_entry( '203.0.113.0/33' ), 'sanitize: /33 rejected' );
ih_assert( false, Ironhide_Core::sanitize_ip_entry( '203.0.113.0/' ), 'sanitize: empty prefix rejected' );
ih_assert( false, Ironhide_Core::sanitize_ip_entry( '203.0.113.0/abc' ), 'sanitize: non-numeric prefix rejected' );
ih_assert( false, Ironhide_Core::sanitize_ip_entry( '999.999.999.999' ), 'sanitize: bad IPv4 rejected' );
ih_assert( false, Ironhide_Core::sanitize_ip_entry( '999.1.1.*' ), 'sanitize: bad wildcard octet rejected' );
ih_assert( false, Ironhide_Core::sanitize_ip_entry( '01.1.1.*' ), 'sanitize: leading-zero wildcard octet rejected' );
ih_assert( false, Ironhide_Core::sanitize_ip_entry( 'hello' ), 'sanitize: junk rejected' );
ih_assert( false, Ironhide_Core::sanitize_ip_entry( array( '1.2.3.4' ) ), 'sanitize: non-scalar rejected' );

// --- entry_is_universal ---------------------------------------------------
ih_assert( true, Ironhide_Core::entry_is_universal( '0.0.0.0/0' ), 'universal: v4 /0' );
ih_assert( true, Ironhide_Core::entry_is_universal( '::/0' ), 'universal: v6 /0' );
ih_assert( true, Ironhide_Core::entry_is_universal( '*.*.*.*' ), 'universal: all-octet wildcard' );
ih_assert( false, Ironhide_Core::entry_is_universal( '203.0.113.0/24' ), 'universal: ordinary /24 is not' );
ih_assert( false, Ironhide_Core::entry_is_universal( '192.168.1.*' ), 'universal: partial wildcard is not' );
ih_assert( false, Ironhide_Core::entry_is_universal( '203.0.113.10' ), 'universal: single address is not' );
ih_assert( false, Ironhide_Core::entry_is_universal( 'junk/0' ), 'universal: invalid network is not' );

// --- get_effective_ip hardening -------------------------------------------
$_SERVER['REMOTE_ADDR'] = '203.0.113.5';
ih_assert( '203.0.113.5', Ironhide_Core::get_effective_ip( array() ), 'effective IP: empty settings falls back to REMOTE_ADDR' );
ih_assert( '203.0.113.5', Ironhide_Core::get_effective_ip( 'nonsense' ), 'effective IP: non-array settings tolerated' );
$_SERVER['HTTP_X_FORWARDED_FOR'] = '198.51.100.1';
ih_assert(
	'203.0.113.5',
	Ironhide_Core::get_effective_ip( array( 'trust_headers' => true ) ),
	'effective IP: trust_headers with no proxy list ignores XFF'
);
unset( $_SERVER['HTTP_X_FORWARDED_FOR'] );

// --- binary_prefix_matches edge -------------------------------------------
ih_assert( true, Ironhide_Core::binary_prefix_matches( "\xcb\x00\x71\x2a", "\xcb\x00\x71\x00", 24 ), 'binary prefix /24' );
ih_assert( false, Ironhide_Core::binary_prefix_matches( "\xcb\x00\x72\x2a", "\xcb\x00\x71\x00", 24 ), 'binary prefix /24 mismatch' );

// --- summary --------------------------------------------------------------
fwrite( STDOUT, "\n$count tests, $failures failure(s)\n" );
exit( $failures > 0 ? 1 : 0 );
