<?php

if( isset( $_POST[ 'Submit' ]  ) ) {
	// Get input
	$target = $_REQUEST[ 'ip' ];

	// Reject anything that isn't a bare IPv4/IPv6 address or hostname before it
	// ever reaches a shell — no shell metacharacters get a foothold.
	if( !filter_var( $target, FILTER_VALIDATE_IP ) &&
		!preg_match( '/^[a-zA-Z0-9.-]+$/', $target ) ) {
		$html .= '<pre>Invalid IP address or hostname.</pre>';
	}
	else {
		// Determine OS and execute the ping command.
		if( stristr( php_uname( 's' ), 'Windows NT' ) ) {
			// Windows
			$cmd = shell_exec( 'ping  ' . escapeshellarg( $target ) );
		}
		else {
			// *nix
			$cmd = shell_exec( 'ping  -c 4 ' . escapeshellarg( $target ) );
		}

		// Feedback for the end user
		$html .= "<pre>{$cmd}</pre>";
	}
}

?>
