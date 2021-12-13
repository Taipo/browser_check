<?php
/*
 * Simple test for a legitimate client. All browsers will not return an expired cookie.
 * Tricky bots often return cookies, but get tripped up with this issue.
 **/
    require_once( 'class_is_browser.php' );
    $isBrowser_Filter = new isBrowser_Filter();
    # choose from either bool, object, json or jbool (json boolean) for output type
    $ip = $_SERVER[ "REMOTE_ADDR" ];
    var_dump( isBrowser_Filter::browser_check( $ip, 'bool' ) );
?>