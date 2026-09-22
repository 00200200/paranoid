<?php

// Only ever redirect to one of this page's own known-good targets — never to
// whatever the client passed in.
$allowed_redirects = array( 'info.php?id=1', 'info.php?id=2' );
if (array_key_exists ("redirect", $_GET) && in_array($_GET['redirect'], $allowed_redirects, true)) {
	header ("location: " . $_GET['redirect']);
	exit;
}

http_response_code (500);
?>
<p>Missing redirect target.</p>
<?php
exit;
?>
