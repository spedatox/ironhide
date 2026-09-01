<?php
/**
 * Minimal block/event logger.
 *
 * Writes tab-separated records to wp-content/uploads/ironhide/ so the site owner
 * can see what is being denied — and, in monitor mode, what *would* be denied —
 * before arming enforcement. The filename carries a salt-derived component so
 * the log cannot be fetched by guessing its URL; see file_name().
 *
 * Tabs are safe as a delimiter because field() strips every control character
 * (0x00-0x1F, which includes TAB, CR and LF) from values, so no user-supplied
 * string can forge a column break or a new record.
 *
 * @package Ironhide
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Logger.
 */
class Ironhide_Logger {

	const MAX_BYTES = 1048576; // 1 MiB, then rotate.
	const MAX_FIELD = 200;     // Per-field character cap.
	const DIR_NAME  = 'ironhide';

	/** Prefix and suffix of the generated log filename. */
	const FILE_PREFIX = 'blocked-';
	const FILE_SUFFIX = '.log';

	/**
	 * Memoised log filename.
	 *
	 * @var string|null
	 */
	private static $file_name = null;

	/**
	 * Record fields, in column order after the timestamp and event.
	 *
	 * @var string[]
	 */
	private static $fields = array( 'ip', 'remote_addr', 'where', 'user', 'bypass', 'uri', 'ua' );

	/**
	 * Column order of a parsed record.
	 *
	 * @return string[]
	 */
	public static function columns() {
		return array_merge( array( 'time', 'event' ), self::$fields );
	}

	/**
	 * Append one record to the block log.
	 *
	 * @param string $event Event name ('block' or 'would_block').
	 * @param array  $data  Field values keyed by name.
	 * @return bool
	 */
	public static function log( $event, $data = array() ) {
		$dir = self::dir();
		if ( '' === $dir ) {
			return false;
		}

		$file = $dir . '/' . self::file_name();
		self::rotate( $file );

		$row = array( gmdate( 'c' ), self::field( $event ) );
		foreach ( self::$fields as $key ) {
			$row[] = self::field( isset( $data[ $key ] ) ? $data[ $key ] : '' );
		}

		$line = implode( "\t", $row ) . "\n";

		return false !== @file_put_contents( $file, $line, FILE_APPEND | LOCK_EX );
	}

	/**
	 * Log filename, with an unguessable component derived from the site salts.
	 *
	 * The log holds security telemetry (the addresses and user agents of refused
	 * requests) and lives under wp-content/uploads, which is web-readable by
	 * default. The .htaccess and web.config guards cover Apache and IIS; nginx
	 * honours neither. A salt-derived filename means the file cannot be fetched
	 * by guessing its URL even when no server rule is in place, so the server
	 * config becomes defence in depth rather than the only defence.
	 *
	 * Rotating the site salts changes the name: the old file is orphaned (and is
	 * cleaned up on uninstall) and logging continues in a fresh one.
	 *
	 * @return string
	 */
	public static function file_name() {
		if ( null === self::$file_name ) {
			self::$file_name = self::FILE_PREFIX
				. substr( hash_hmac( 'sha256', 'ironhide-block-log', wp_salt( 'auth' ) ), 0, 16 )
				. self::FILE_SUFFIX;
		}
		return self::$file_name;
	}

	/**
	 * Absolute path of the log directory. Does not touch the filesystem.
	 *
	 * @return string Directory path, or '' when uploads are unavailable.
	 */
	public static function dir_path() {
		$up   = wp_upload_dir();
		$base = isset( $up['basedir'] ) ? $up['basedir'] : '';
		if ( ! is_string( $base ) || '' === $base ) {
			return '';
		}
		return trailingslashit( $base ) . self::DIR_NAME;
	}

	/**
	 * Absolute path of the log file, or ''.
	 *
	 * @return string
	 */
	public static function file_path() {
		$dir = self::dir_path();
		return ( '' === $dir ) ? '' : $dir . '/' . self::file_name();
	}

	/**
	 * Log directory, created and protected if needed.
	 *
	 * @return string Directory path, or '' when unavailable.
	 */
	public static function dir() {
		$dir = self::dir_path();
		if ( '' === $dir ) {
			return '';
		}

		if ( ! is_dir( $dir ) && ! wp_mkdir_p( $dir ) ) {
			return '';
		}

		self::protect_dir( $dir );

		return $dir;
	}

	/**
	 * (Re)create the files that keep the log directory off the web.
	 *
	 * Checked on every write, not only at creation, so a directory that already
	 * existed — or one whose guard files were deleted — still gets protected.
	 *
	 * @param string $dir Directory path.
	 * @return void
	 */
	public static function protect_dir( $dir ) {
		$guards = array(
			// Prevent directory listing.
			'index.php'  => "<?php // Silence is golden.\n",
			// Deny direct web access on Apache.
			'.htaccess'  => "# Deny all web access to the Ironhide log directory.\n" .
				"<IfModule mod_authz_core.c>\nRequire all denied\n</IfModule>\n" .
				"<IfModule !mod_authz_core.c>\nOrder deny,allow\nDeny from all\n</IfModule>\n",
			// Deny direct web access on IIS.
			'web.config' => "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n" .
				"<configuration>\n  <system.webServer>\n    <authorization>\n" .
				"      <deny users=\"*\" />\n    </authorization>\n" .
				"  </system.webServer>\n</configuration>\n",
		);

		foreach ( $guards as $name => $contents ) {
			$path = $dir . '/' . $name;
			if ( ! file_exists( $path ) ) {
				@file_put_contents( $path, $contents );
			}
		}
		// nginx honours none of the above — see README.md for the location rule.
	}

	/**
	 * Every file this plugin creates in the log directory.
	 *
	 * Used by uninstall.php so the directory is actually empty before rmdir().
	 *
	 * @return string[]
	 */
	public static function owned_files() {
		return array( self::file_name(), self::file_name() . '.1', 'index.php', '.htaccess', 'web.config' );
	}

	/**
	 * Rotate the log once it exceeds the size cap.
	 *
	 * @param string $file Log file path.
	 * @return void
	 */
	public static function rotate( $file ) {
		if ( ! is_file( $file ) ) {
			return;
		}
		$size = @filesize( $file );
		if ( false !== $size && $size > self::MAX_BYTES ) {
			@rename( $file, $file . '.1' );
		}
	}

	/**
	 * The most recent records, newest first.
	 *
	 * Reads only the tail of the file, so a large log costs a bounded amount of
	 * memory.
	 *
	 * @param int $limit Maximum records to return.
	 * @return array[] List of associative records keyed by columns().
	 */
	public static function recent( $limit = 20 ) {
		$limit = max( 1, (int) $limit );
		$file  = self::file_path();

		if ( '' === $file || ! is_file( $file ) || ! is_readable( $file ) ) {
			return array();
		}

		$size = @filesize( $file );
		if ( ! $size ) {
			return array();
		}

		$window = (int) min( $size, 64 * 1024 );
		$handle = @fopen( $file, 'rb' );
		if ( ! $handle ) {
			return array();
		}
		@fseek( $handle, -$window, SEEK_END );
		$buffer = @fread( $handle, $window );
		@fclose( $handle );

		if ( ! is_string( $buffer ) || '' === $buffer ) {
			return array();
		}

		$lines = preg_split( '/\r?\n/', $buffer, -1, PREG_SPLIT_NO_EMPTY );
		if ( empty( $lines ) ) {
			return array();
		}

		// The first line may be a fragment when the window cut mid-record.
		if ( $window < $size && count( $lines ) > 1 ) {
			array_shift( $lines );
		}

		$lines = array_slice( $lines, -$limit );

		$records = array();
		foreach ( array_reverse( $lines ) as $line ) {
			$records[] = self::parse_line( $line );
		}

		return $records;
	}

	/**
	 * Split one stored record back into named fields.
	 *
	 * Unparseable lines come back with the raw text in `event`, so nothing is
	 * silently dropped from the display.
	 *
	 * @param string $line Stored line.
	 * @return array
	 */
	public static function parse_line( $line ) {
		$columns = self::columns();
		$record  = array_fill_keys( $columns, '' );
		$parts   = explode( "\t", $line );

		if ( count( $parts ) < 2 ) {
			$record['event'] = trim( $line );
			return $record;
		}

		foreach ( $columns as $i => $column ) {
			$record[ $column ] = isset( $parts[ $i ] ) ? $parts[ $i ] : '';
		}

		return $record;
	}

	/**
	 * Sanitise a single log field (strip control chars, cap length).
	 *
	 * Prevents column/record forging via a hostile User-Agent or request URI.
	 *
	 * @param mixed $value Raw value.
	 * @return string
	 */
	public static function field( $value ) {
		if ( is_array( $value ) || is_object( $value ) ) {
			$value = '';
		}
		$value = (string) $value;
		$value = preg_replace( '/[\x00-\x1f\x7f]+/', ' ', $value );
		$value = substr( $value, 0, self::MAX_FIELD );
		return ( '' === $value ) ? '-' : $value;
	}

	/**
	 * Remove the bypass-key value from a request URI before logging.
	 *
	 * The key is a secret; never write it to a file.
	 *
	 * @param string $uri Request URI.
	 * @return string
	 */
	public static function redact_uri( $uri ) {
		return preg_replace(
			'/([?&]' . preg_quote( Ironhide_Recovery::QUERY_KEY, '/' ) . '=)[^&#]*/i',
			'$1[redacted]',
			(string) $uri
		);
	}
}
