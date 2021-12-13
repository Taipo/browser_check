<?php

# Credit for this concept goes to Mike Parniak who first
# published this idea in his security class ccisecurity.php

class isBrowser_Filter {
	const MOMO_HAATEPE = 'sha3-512';
	const TAUROA = '[add__your_random_pepper_hash]';
	const HASH_TYPE = 9; // sha512
	const SESS_TIME = 3600;
    
	public static function browser_check( $ip = '' ): bool {
		if ( substr_count( $_SERVER[ "SERVER_NAME" ], "." ) > 1 ) {
			$cookiedomain = preg_replace( "^[^\.]+\.", ".", $_SERVER[ "SERVER_NAME" ] );
		} else $cookiedomain = "." . $_SERVER[ "SERVER_NAME" ];

		# most of what you see below is about getting a unique session hash.
		# this is not needed for this exercise, $mysession = sha1( $ip . $_SERVER[ 'HTTP_HOST' ] . self::TAUROA ) would
		# work just fine as a test
		$mysession = hash( 'sha512', $ip . self::get_server_sig() . self::get_time_hash() );
		$browser_hash = hash( 'sha512', $ip . self::get_server_sig() );
		session_id( $mysession );
		session_start();
		# while the session will be set, some flooder tools for example will arbitrarily return every cookie sent in the http header
		# whereas all browsers will simply not return the cookie
		if ( ( isset( $_SESSION[ "browser-test-" . $browser_hash ] ) ) && ( isset( $_COOKIE[ $_SESSION[ "browser-test-" . $browser_hash ] ] ) ) ) {
			return false;
		}
		$test_string = hash( 'sha512', uniqid( time() ) );
		# set an expired cookie
		setcookie( $test_string, hash( 'sha512', uniqid( time() ) ), time() - rand( 900000, 999999 ), "/", $cookiedomain );
		$_SESSION[ "browser-test-" . $browser_hash ] = $test_string;
		#$output = self::clear_session();  
		session_write_close();
		return true;
	}
	# Most of these functions are just overkill to achieve a strong unique hash
	# To use IP banning in a production situation you would also need to detect 
	# Cloudflare and Quick Cloud to prevent banning of server or upline IP addresses
	
	# kaakano tupurangi
	public static function kakano_tupokanoa() {
		return abs( crc32( self::whakahaatepe( static::MOMO_HAATEPE, ( hexdec( substr( microtime(), -8 ) ) & 0x7fffffff ), true ) ) );
	}
	public static function whakahaatepe( $momo_aho, $taauru, $whakatote = false ) {
		$momo_haatepe = self::momo_aho( $momo_aho );
		if ( false !== $whakatote ) {
			$pepa = base64_encode( random_bytes( 64 ) );
		}
		return hash( $momo_haatepe, hash_pbkdf2( $momo_haatepe, $taauru, ( ( false !== $whakatote ) ? $pepa : NULL ), 24576, 96, true ) );
	}
	public static function momo_aho( $momo_aho ) {
		if ( is_int( $momo_aho ) ) {
			foreach ( hash_algos() as $kii => $uara ) {
				if ( $kii == $momo_aho ) {
					return $uara;
				}
			}
		} else {
			if ( in_array( $momo_aho, hash_algos() ) ) return $momo_aho;
		}
	}
	public static function clear_session() {
		$getvariables = array_keys( $_SESSION );
		if ( empty( $getvariables ) ) return;
		$count = 0;
		while( $count < count( $getvariables ) ) {
			if ( substr( $getvariables[ $count ], 0, 12 ) == 'browser-test' ) {
				unset( $_SESSION[ $getvariables[ $count ] ] );
			}
		$count++;
		}
		return true;
	}
	public static function get_server_sig( $rand = false ) {
		if ( false !== $rand ) return base64_encode( random_bytes( 24 ) );
		# aggregate static variables
		$_SERVERVARS = '';
		$serverVars  = array(
			'HTTP_HOST',
			'SERVER_ADMIN',
			'HTTP_USER_AGENT',
			'SERVER_ADDR',
			'REMOTE_ADDR',
			'DOCUMENT_ROOT',
			'HTTP_ACCEPT',
			'HTTP_X_CLUSTER_CLIENT_IP',
			'HTTP_X_FORWARDED_FOR',
			'HTTP_X_ORIGINAL_URL',
			'HTTP_CONNECTION',
			'HTTP_X_REWRITE_URL',
			'HTTP_CLIENT_IP',
			'HTTP_PROXY_USER',
			'GATEWAY_INTERFACE',
			'SERVER_SOFTWARE',
			'SERVER_PROTOCOL',
			'HTTP_ACCEPT_ENCODING',
			'HTTP_ACCEPT_LANGUAGE',
			'PATH',
			'SERVER_SIGNATURE',
			'SERVER_SOFTWARE',
			'SERVER_NAME',
			'SERVER_ADDR',
			'SERVER_PORT',
		);
		$x = 0;
		while ( $x < count( $serverVars ) ) {
			if ( false !== isset( $_SERVER[ $serverVars[ $x ] ] ) )
				$_SERVERVARS = $_SERVERVARS . $_SERVER[ $serverVars[ $x ] ];
			$x++;
		}
		return self::make_hash( self::HASH_TYPE, preg_replace( "/[\s]/i", '', self::TAUROA . $_SERVERVARS ) );
	}
	public static function make_hash( $sType, $input, $withSalt = false ) {
		$hashtype = self::get_hash_type( $sType );
		// format: algorithm:iterations:salt:hash
		if ( false !== $withSalt )
			$salt = base64_encode( random_bytes( 24 ) );
		return hash( $hashtype, hash_pbkdf2( $hashtype, $input, ( ( false !== $withSalt ) ? $salt : NULL ), 4096, 96 ) );
	}
	public static function get_hash_type( $sType ) {
		foreach ( hash_algos() as $key => $val ) {
			if ( $key == $sType ) {
				return $val;
			}
		}
		return;
	}	 
	public static function get_time_hash() {
		$time_array   = explode( ' ', gmdate( 'D, d M Y H:i:s', time() + ( 12 * 3600 ) ) );
		$dlis = array(
				"Monday",
				"Tuesday",
				"Wednesday",
				"Thursday",
				"Friday",
				"Saturday",
				"Sunday" 
			 );
		$mlist	= array(
				"January",
				"February",
				"March",
				"April",
				"May",
				"June",
				"July",
				"August",
				"September",
				"October",
				"November",
				"December" 
			);
		$fullmonth	= static::make_hash( self::HASH_TYPE, $mlist[ ( ( int ) gmdate( "m" ) ) - 1 ] . self::SESS_TIME );
		for ( $x = 0; $x < count( $dlist ); $x++ ) {
			if ( false !== strpos( $dlist[ $x ], gmdate( "D" ) ) ) {
				$fullday = static::make_hash( self::HASH_TYPE, $dlist[ $x ] );
				break;
			}
		}
		$ampm	= static::make_hash( self::HASH_TYPE, ( ( int ) substr( $time_array[ 4 ], 0, 2 ) > 11 ) ? 'PM' . $fullday : 'AM' . $fullmonth );
		return static::make_hash( self::HASH_TYPE, ( substr( preg_replace( "/[\s]/i", '', gmdate( 'D, d M Y H:i:s', time() + ( 12 * 3600 ) ) ), 0, ( int ) strpos( preg_replace( "/[\s]/i", '', gmdate( 'D, d M Y H:i:s', time() + ( 12 * 3600 ) ) ), ":" ) ) . ( isset( $_SERVER[ 'REQUEST_TIME_FLOAT' ] ) ? substr( $_SERVER[ 'REQUEST_TIME_FLOAT' ], 0, 6 ) : substr( $_SERVER[ 'REQUEST_TIME' ], 0, 7 ) ) ) );		
	}
}
?>
