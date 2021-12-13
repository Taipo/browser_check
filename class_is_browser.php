<?php
class isBrowser_Filter {
    const MOMO_HAATEPE = 'sha3-512';
    const TAUROA = 'teuNLiRQVvncPCQvxPba3WvHAQN8Eje9vqi9kRf7PiGBw22m9wJ79i9JyiXPbiFK';
    const HASH_TYPE = 9;
    const SESS_TIME = 3600;
    
    public static function browser_check( $ip = '' ): bool {
        if ( substr_count( $_SERVER[ "SERVER_NAME" ], "." ) > 1 ) {
            $cookiedomain = preg_replace( "^[^\.]+\.", ".", $_SERVER[ "SERVER_NAME" ] );
        } else $cookiedomain = "." . $_SERVER[ "SERVER_NAME" ];
        
        $mysession = hash( 'sha512', $ip . self::get_server_sig() . self::get_time_hash() );						
        session_id( $mysession );
        session_start();
        if ( ( isset( $_SESSION[ "browser-test" ] ) ) && ( isset( $_COOKIE[ $_SESSION[ "browser-test" ] ] ) ) ) {
          return false;
        }
        $test_string = hash('sha512', uniqid( time() ) );
        setcookie( $test_string, hash('sha512', uniqid( time() ) ), time()-999999, "/", $cookiedomain );
        $_SESSION[ "browser-test-" . self::kakano_tupokanoa() ] = $test_string;
        $output = self::clear_session();  
        session_write_close();
        return true;
    }
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
         $x           = 0;
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
     public static function pbkdf2( $algorithm, $password, $salt, $count, $key_length, $raw_output = false ) {
         $algorithm = strtolower( $algorithm );
         if ( !in_array( $algorithm, hash_algos(), true ) )
             die( 'PBKDF2 ERROR: Invalid hash algorithm.' );
         if ( $count <= 0 || $key_length <= 0 )
             die( 'PBKDF2 ERROR: Invalid parameters.' );
         $hash_length = strlen( hash( $algorithm, "", true ) );
         $block_count = ceil( $key_length / $hash_length );
         $output      = "";
         for ( $i = 1; $i <= $block_count; $i++ ) {
             // $i encoded as 4 bytes, big endian.
             $last = $salt . pack( "N", $i );
             // first iteration
             $last = $xorsum = hash_hmac( $algorithm, $last, $password, true );
             // perform the other $count - 1 iterations
             for ( $j = 1; $j < $count; $j++ ) {
                 $xorsum ^= ( $last = hash_hmac( $algorithm, $last, $password, true ) );
             }
             $output .= $xorsum;
         }
         if ( $raw_output )
             return substr( $output, 0, $key_length );
         else
             return bin2hex( substr( $output, 0, $key_length ) );
     }
     public static function get_time_hash() {
         $time_array   = explode( ' ', gmdate( 'D, d M Y H:i:s', time() + ( 12 * 3600 ) ) );
         $dlist        = array(
								"Monday",
								"Tuesday",
								"Wednesday",
								"Thursday",
								"Friday",
								"Saturday",
								"Sunday" 
                                );
         $mlist        = array(
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
         $fullmonth    = static::make_hash( self::HASH_TYPE, $mlist[ ( ( int ) gmdate( "m" ) ) - 1 ] . self::SESS_TIME );
         for ( $x = 0; $x < count( $dlist ); $x++ ) {
             if ( false !== strpos( $dlist[ $x ], gmdate( "D" ) ) ) {
                 $fullday = static::make_hash( self::HASH_TYPE, $dlist[ $x ] );
                 break;
             }
         }
         $ampm       = static::make_hash( self::HASH_TYPE, ( ( int ) substr( $time_array[ 4 ], 0, 2 ) > 11 ) ? 'PM' . $fullday : 'AM' . $fullmonth );
         return static::make_hash( self::HASH_TYPE, ( substr( preg_replace( "/[\s]/i", '', gmdate( 'D, d M Y H:i:s', time() + ( 12 * 3600 ) ) ), 0, ( int ) strpos( preg_replace( "/[\s]/i", '', gmdate( 'D, d M Y H:i:s', time() + ( 12 * 3600 ) ) ), ":" ) ) . ( isset( $_SERVER[ 'REQUEST_TIME_FLOAT' ] ) ? substr( $_SERVER[ 'REQUEST_TIME_FLOAT' ], 0, 6 ) : substr( $_SERVER[ 'REQUEST_TIME' ], 0, 7 ) ) ) );        
     }
    function is_cf( $this_ip ) {
        error_reporting( 0 );
        $_get_server = $_SERVER;
        if ( isset( $_get_server[ 'HTTP_CF_CONNECTING_IP' ] ) ||
             isset( $_get_server[ 'HTTP_CDN_LOOP' ] ) ||
             isset( $_get_server[ 'HTTP_CF_VISITOR' ] ) ||
             isset( $_get_server[ 'HTTP_CF_RAY' ] ) ||
             isset( $_get_server[ 'HTTP_CF_IPCOUNTRY' ] ) ) {
            # Cloudflare is enabled
            # Harden IP Check against spoofing of CF IPs
            $cf_ipv4_ranges = '';
            $cf_ipv4_ranges = array(
                                '173.245.48.0/20',
                                '103.21.244.0/22',
                                '103.22.200.0/22',
                                '103.31.4.0/22',
                                '141.101.64.0/18',
                                '108.162.192.0/18',
                                '190.93.240.0/20',
                                '188.114.96.0/20',
                                '197.234.240.0/22',
                                '198.41.128.0/17',
                                '162.158.0.0/15',
                                '172.64.0.0/13',
                                '131.0.72.0/22',
                                '104.16.0.0/13',
                                '104.24.0.0/14'
                                );
            $cf_ipv6_ranges = '';
            $cf_ipv6_ranges = array(
                                '2400:cb00::/32',
                                '2606:4700::/32',
                                '2803:f800::/32',
                                '2405:b500::/32',
                                '2405:8100::/32',
                                '2a06:98c0::/29',
                                '2c0f:f248::/32'
                                );
            
             $valid_cf_req = false;
             foreach( $cf_ipv4_ranges as $range ) {
                if ( $this->ip_inrange( $this_ip, $range ) ) {
                    $valid_cf_req = true;
                    break;
                }
             }
             foreach( $cf_ipv6_ranges as $range ) {
                if ( $this->ip_inrange( $this_ip, $range ) ) {
                    $valid_cf_req = true;
                    break;
                }
             }             
             $this_cf_ip = '';
             if ( false !== $valid_cf_req ) {
                error_reporting( 6135 );
                if ( isset( $_get_server[ 'HTTP_TRUE_CLIENT_IP' ] ) && $this->check_ip( $_get_server[ 'HTTP_TRUE_CLIENT_IP' ] ) ) {
                    if ( false === $this->get_serverip() ) $this_cf_ip = $_get_server[ 'HTTP_TRUE_CLIENT_IP' ];
                } elseif ( isset( $_get_server[ 'HTTP_CF_CONNECTING_IP' ] ) && $this->check_ip( $_get_server[ 'HTTP_CF_CONNECTING_IP' ] ) ) {
                    if ( false === $this->get_serverip() ) $this_cf_ip = $_get_server[ 'HTTP_CF_CONNECTING_IP' ];
                }
                # these are server ips within the Cloudflare CDN, so do not ban
                return $this_cf_ip;
             } else return false;
        } else return false;
    }
    function is_qc( $this_ip ) {
            error_reporting( 0 );
            # Harden IP Check against spoofing of Quick Cloud IPs
            $qc_ip_ranges = array(
                            '102.129.254.77',
                            '102.221.36.98',
                            '102.221.36.99',
                            '103.13.113.249',
                            '103.152.118.219',
                            '103.152.118.72',
                            '103.164.203.163',
                            '103.199.16.151',
                            '103.236.150.198',
                            '103.236.150.223',
                            '103.28.90.190',
                            '104.225.142.116',
                            '109.248.43.212',
                            '124.150.139.239',
                            '135.148.120.32',
                            '135.148.148.230',
                            '137.220.36.137',
                            '139.162.89.149',
                            '139.59.21.152',
                            '141.164.38.65',
                            '146.59.17.163',
                            '146.88.239.197',
                            '147.135.115.64',
                            '149.28.11.90',
                            '152.228.171.66',
                            '154.16.57.184',
                            '156.67.209.151',
                            '163.182.174.161',
                            '163.47.20.24',
                            '163.47.21.168',
                            '164.52.202.100',
                            '165.227.116.222',
                            '172.104.44.18',
                            '178.17.171.177',
                            '18.192.146.200',
                            '181.215.183.135',
                            '185.108.129.52',
                            '185.116.60.231',
                            '185.116.60.232',
                            '185.126.236.167',
                            '185.126.237.129',
                            '185.205.187.233',
                            '185.228.26.40',
                            '185.243.215.148',
                            '185.53.57.40',
                            '185.53.57.89',
                            '192.99.38.117',
                            '193.203.202.215',
                            '194.36.144.221',
                            '195.231.17.141',
                            '199.59.247.242',
                            '2.58.28.32',
                            '200.58.127.145',
                            '204.10.163.237',
                            '207.246.71.239',
                            '209.208.26.218',
                            '213.159.1.75',
                            '213.183.51.224',
                            '213.184.87.75',
                            '216.250.96.181',
                            '27.131.75.40',
                            '27.131.75.41',
                            '31.131.4.244',
                            '31.22.115.186',
                            '31.220.111.172',
                            '37.120.131.40',
                            '37.143.128.237',
                            '38.129.107.18',
                            '41.185.29.210',
                            '41.223.53.163',
                            '43.231.0.46',
                            '45.124.65.86',
                            '45.132.244.92',
                            '45.248.77.61',
                            '45.32.210.159',
                            '45.56.77.123',
                            '45.76.17.119',
                            '45.9.249.220',
                            '46.250.220.133',
                            '49.12.102.29',
                            '5.134.119.103',
                            '5.134.119.194',
                            '5.188.183.13',
                            '51.81.186.219',
                            '51.81.33.156',
                            '54.162.162.165',
                            '54.36.103.97',
                            '62.141.42.38',
                            '64.225.34.246',
                            '64.227.16.93',
                            '65.21.81.50',
                            '65.21.81.51',
                            '74.3.163.74',
                            '79.172.239.249',
                            '81.31.156.246',
                            '83.229.71.151',
                            '86.105.14.231',
                            '86.105.14.232',
                            '91.201.67.57',
                            '91.228.7.67',
                            '91.239.234.48',
                            '92.223.105.192',
                            '92.38.139.226',
                            '93.95.227.66',
                            '94.26.84.39',
                            '94.75.232.90',
                            '95.217.200.8'
                                                        );
            error_reporting( 6135 );
            if ( in_array( $this_ip, $qc_ip_ranges ) ) {
                return true; // this will prevent Quick.cloud from being IP banned
            } else return false;    
    }    
}
?>