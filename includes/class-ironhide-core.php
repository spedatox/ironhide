<?php
/**
 * IP parsing, matching and request-IP detection.
 *
 * This class is deliberately free of WordPress dependencies so the matching
 * logic can be unit-tested in isolation. The only proxy-aware concern
 * (forwarding-header handling) is driven entirely by the settings array.
 *
 * @package Ironhide
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Core IP utilities.
 */
class Ironhide_Core {

	/**
	 * Read one server variable as a trimmed string (or '' when absent).
	 *
	 * @param string $key Server array key, e.g. 'REMOTE_ADDR'.
	 * @return string
	 */
	public static function server_var( $key ) {
		if ( isset( $_SERVER[ $key ] ) && is_string( $_SERVER[ $key ] ) ) {
			return trim( $_SERVER[ $key ] );
		}
		return '';
	}

	/**
	 * The immediate peer address as reported by the web server.
	 *
	 * This is the only value that cannot be spoofed by a client. Forwarding
	 * headers are handled separately in get_effective_ip(), and only when the
	 * peer is a recognised proxy.
	 *
	 * @return string
	 */
	public static function get_remote_addr() {
		return self::server_var( 'REMOTE_ADDR' );
	}

	/**
	 * Resolve the single IP address the guard will evaluate.
	 *
	 * The returned value is the same IP that ip_in_list() compares, which is
	 * also the IP the settings screen adds to the allowlist on save. Keeping
	 * that one source of truth is what makes the "never lock yourself out on
	 * save" guarantee hold.
	 *
	 * @param array $settings Merged plugin settings.
	 * @return string IP address, or '' when it cannot be determined.
	 */
	public static function get_effective_ip( $settings ) {
		$remote = self::get_remote_addr();

		if ( ! is_array( $settings ) ) {
			$settings = array();
		}

		// Default: trust only the web server, never client-supplied headers.
		if ( empty( $settings['trust_headers'] ) ) {
			return self::normalize_ip( $remote );
		}

		$proxies = ( isset( $settings['trusted_proxies'] ) && is_array( $settings['trusted_proxies'] ) )
			? $settings['trusted_proxies']
			: array();

		// Trust forwarding headers ONLY when the immediate peer is a proxy we
		// recognise. Otherwise X-Forwarded-For is attacker-controlled.
		if ( ! self::ip_in_list( $remote, $proxies ) ) {
			return self::normalize_ip( $remote );
		}

		// X-Forwarded-For grows left-to-right as each proxy appends the address
		// it received from. Walk it from the right and return the first
		// non-proxy address: the real client as seen by the first trusted proxy.
		$xff = self::server_var( 'HTTP_X_FORWARDED_FOR' );
		if ( '' !== $xff ) {
			$chain = array_map( 'trim', explode( ',', $xff ) );
			for ( $i = count( $chain ) - 1; $i >= 0; $i-- ) {
				if ( '' === $chain[ $i ] ) {
					continue;
				}
				if ( ! self::ip_in_list( $chain[ $i ], $proxies ) ) {
					return self::normalize_ip( $chain[ $i ] );
				}
			}
		}

		// Fall back to X-Real-IP (nginx proxy_set_header), then the peer itself.
		$real = self::server_var( 'HTTP_X_REAL_IP' );
		if ( '' !== $real ) {
			return self::normalize_ip( $real );
		}

		return self::normalize_ip( $remote );
	}

	/**
	 * Normalise an IP for comparison.
	 *
	 * Lowercases, strips IPv6 zone ids, and converts IPv4-mapped IPv6
	 * (::ffff:1.2.3.4) back to plain IPv4 so the same host never fails to match
	 * itself when it appears once as v4 and once as mapped v6.
	 *
	 * @param mixed $ip Raw IP value.
	 * @return string Normalised IP, or '' when invalid.
	 */
	public static function normalize_ip( $ip ) {
		if ( ! is_scalar( $ip ) ) {
			return '';
		}

		$ip = trim( (string) $ip );
		if ( '' === $ip ) {
			return '';
		}

		$ip = strtolower( $ip );

		// Strip IPv6 zone index, e.g. fe80::1%eth0.
		$zone = strpos( $ip, '%' );
		if ( false !== $zone ) {
			$ip = substr( $ip, 0, $zone );
		}

		$bin = @inet_pton( $ip );
		if ( false === $bin ) {
			return '';
		}

		if ( 16 === strlen( $bin ) ) {
			// IPv4-mapped IPv6.
			$mapped = "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff";
			if ( $mapped === substr( $bin, 0, 12 ) ) {
				return inet_ntop( substr( $bin, 12, 4 ) );
			}
		}

		return inet_ntop( $bin );
	}

	/**
	 * Is $ip allowed by a list of exact / CIDR / wildcard entries?
	 *
	 * @param string $ip   Client IP.
	 * @param array  $list Array of allowlist entries.
	 * @return bool
	 */
	public static function ip_in_list( $ip, $list ) {
		if ( '' === $ip || ! is_array( $list ) ) {
			return false;
		}
		foreach ( $list as $entry ) {
			if ( self::ip_matches_entry( $ip, $entry ) ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Match one IP against one entry (exact, CIDR, or IPv4 wildcard).
	 *
	 * @param string $ip    Client IP.
	 * @param mixed  $entry Allowlist entry.
	 * @return bool
	 */
	public static function ip_matches_entry( $ip, $entry ) {
		if ( ! is_scalar( $entry ) ) {
			return false;
		}

		$entry = trim( (string) $entry );
		if ( '' === $entry ) {
			return false;
		}

		if ( false !== strpos( $entry, '*' ) ) {
			return self::wildcard_match( $ip, $entry );
		}

		if ( false !== strpos( $entry, '/' ) ) {
			return self::cidr_match( $ip, $entry );
		}

		$normalized = self::normalize_ip( $ip );

		return ( '' !== $normalized && $normalized === self::normalize_ip( $entry ) );
	}

	/**
	 * Match an IP against a CIDR range (IPv4 or IPv6).
	 *
	 * @param string $ip   Client IP.
	 * @param string $cidr Range in "network/prefix" form.
	 * @return bool
	 */
	public static function cidr_match( $ip, $cidr ) {
		$cidr  = trim( (string) $cidr );
		$slash = strrpos( $cidr, '/' );

		if ( false === $slash ) {
			return self::ip_matches_entry( $ip, $cidr );
		}

		$network = substr( $cidr, 0, $slash );
		$bits    = substr( $cidr, $slash + 1 );

		// Reject empty / non-numeric prefixes rather than letting the cast turn
		// "1.2.3.0/" into /0, which would match every address.
		$bits = trim( $bits );
		if ( '' === $bits || ! ctype_digit( $bits ) ) {
			return false;
		}

		$ip_bin  = self::binary_ip( $ip );
		$net_bin = self::binary_ip( $network );

		if ( false === $ip_bin || false === $net_bin || strlen( $ip_bin ) !== strlen( $net_bin ) ) {
			return false;
		}

		$bitlen = strlen( $net_bin ) * 8;
		$bits   = (int) $bits;

		if ( $bits < 0 || $bits > $bitlen ) {
			return false;
		}

		return self::binary_prefix_matches( $ip_bin, $net_bin, $bits );
	}

	/**
	 * Match an IPv4 address against a dotted wildcard, e.g. 192.168.*.*.
	 *
	 * @param string $ip      Client IP.
	 * @param string $pattern Wildcard pattern.
	 * @return bool
	 */
	public static function wildcard_match( $ip, $pattern ) {
		$ip = self::normalize_ip( $ip );
		if ( false === filter_var( $ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 ) ) {
			return false;
		}

		$ipo = explode( '.', $ip );
		$pat = explode( '.', strtolower( trim( (string) $pattern ) ) );

		if ( 4 !== count( $ipo ) || 4 !== count( $pat ) ) {
			return false;
		}

		for ( $i = 0; $i < 4; $i++ ) {
			if ( '*' === $pat[ $i ] ) {
				continue;
			}
			if ( $pat[ $i ] !== $ipo[ $i ] ) {
				return false;
			}
		}

		return true;
	}

	/**
	 * Validate and normalise a single user-supplied entry for saving.
	 *
	 * @param mixed $entry Raw entry.
	 * @return string|false Normalised entry, or false when invalid.
	 */
	public static function sanitize_ip_entry( $entry ) {
		if ( ! is_scalar( $entry ) ) {
			return false;
		}

		$entry = trim( (string) $entry );
		if ( '' === $entry ) {
			return false;
		}

		// IPv4 wildcard.
		if ( false !== strpos( $entry, '*' ) ) {
			$octet = '(?:\*|25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)';
			$ok    = preg_match( '/^' . $octet . '(?:\.' . $octet . '){3}$/', $entry );
			return $ok ? strtolower( $entry ) : false;
		}

		// CIDR.
		if ( false !== strpos( $entry, '/' ) ) {
			$parts = explode( '/', $entry );
			if ( 2 === count( $parts ) ) {
				$net    = self::normalize_ip( $parts[0] );
				$bin    = ( '' === $net ) ? false : @inet_pton( $net );
				$prefix = trim( $parts[1] );
				// Reject empty / non-numeric prefixes before casting, otherwise
				// "1.2.3.0/" and "1.2.3.0/abc" would silently become /0.
				if ( false !== $bin && '' !== $prefix && ctype_digit( $prefix ) ) {
					$bits = (int) $prefix;
					$max  = ( 4 === strlen( $bin ) ) ? 32 : 128;
					if ( $bits >= 0 && $bits <= $max ) {
						return $net . '/' . $bits;
					}
				}
			}
			return false;
		}

		$normalized = self::normalize_ip( $entry );
		return ( '' === $normalized ) ? false : $normalized;
	}

	/**
	 * Does this entry match every address of its family?
	 *
	 * A `/0` range or an all-wildcard pattern is syntactically valid but turns
	 * the allowlist into "allow everyone", silently disabling protection. The
	 * settings screen warns rather than rejecting, since an operator may mean it.
	 *
	 * @param string $entry Normalised allowlist entry.
	 * @return bool
	 */
	public static function entry_is_universal( $entry ) {
		if ( ! is_scalar( $entry ) ) {
			return false;
		}

		$entry = trim( strtolower( (string) $entry ) );
		if ( '' === $entry ) {
			return false;
		}

		if ( '*.*.*.*' === $entry ) {
			return true;
		}

		$slash = strrpos( $entry, '/' );
		if ( false === $slash ) {
			return false;
		}

		$bits = substr( $entry, $slash + 1 );

		return ( ctype_digit( $bits ) && 0 === (int) $bits && false !== self::binary_ip( substr( $entry, 0, $slash ) ) );
	}

	/**
	 * Binary (inet_pton) form of an IP, or false when invalid.
	 *
	 * @param string $ip IP string.
	 * @return string|false
	 */
	public static function binary_ip( $ip ) {
		$ip = self::normalize_ip( $ip );
		if ( '' === $ip ) {
			return false;
		}
		$bin = @inet_pton( $ip );
		return ( false === $bin ) ? false : $bin;
	}

	/**
	 * Compare the leading $bits bits of two binary IPs.
	 *
	 * @param string $ip_bin  Binary client IP.
	 * @param string $net_bin Binary network address.
	 * @param int    $bits    Prefix length.
	 * @return bool
	 */
	public static function binary_prefix_matches( $ip_bin, $net_bin, $bits ) {
		$full = $bits >> 3; // Whole bytes.
		$rem  = $bits & 7;  // Remaining bits.

		if ( $full > 0 && substr( $ip_bin, 0, $full ) !== substr( $net_bin, 0, $full ) ) {
			return false;
		}

		if ( $rem > 0 ) {
			$mask = ( 0xff << ( 8 - $rem ) ) & 0xff;
			if ( ( ord( $ip_bin[ $full ] ) & $mask ) !== ( ord( $net_bin[ $full ] ) & $mask ) ) {
				return false;
			}
		}

		return true;
	}
}
