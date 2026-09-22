<?php

if( isset( $_POST[ 'Upload' ] ) ) {
	// Where are we going to be writing to?
	$uploaded_name = basename( $_FILES[ 'uploaded' ][ 'name' ] );
	$uploaded_ext  = strtolower( substr( $uploaded_name, strrpos( $uploaded_name, '.' ) + 1 ) );
	$target_path   = DVWA_WEB_PAGE_TO_ROOT . "hackable/uploads/" . $uploaded_name;

	// Only accept real images: allow-listed extension plus a valid image
	// header, so a .php file (with or without a spoofed Content-Type) is
	// rejected before it ever reaches the uploads folder.
	if( !in_array( $uploaded_ext, array( 'jpg', 'jpeg', 'png' ), true ) ||
		$_FILES[ 'uploaded' ][ 'size' ] >= 100000 ||
		!getimagesize( $_FILES[ 'uploaded' ][ 'tmp_name' ] ) ) {
		$html .= '<pre>Your image was not uploaded. We can only accept JPEG or PNG images.</pre>';
	}
	// Can we move the file to the upload folder?
	else if( !move_uploaded_file( $_FILES[ 'uploaded' ][ 'tmp_name' ], $target_path ) ) {
		// No
		$html .= '<pre>Your image was not uploaded.</pre>';
	}
	else {
		// Yes!
		$html .= "<pre>{$target_path} succesfully uploaded!</pre>";
	}
}

?>
