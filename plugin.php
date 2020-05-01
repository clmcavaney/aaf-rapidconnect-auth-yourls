<?php
/*
Plugin Name: AAF Rapid Connect Authentication
Plugin URI: https://github.com/clmcavaney/aaf-rapidconnect-auth-yourls
Description: This plugin enables authentation against AAF Rapid Connect
Version: 1.1
Author: Christopher McAvaney
Author URI: http://deakinresear.ch/eresearch
*/

// No direct call
if( !defined( 'YOURLS_ABSPATH' ) ) die();

/* The function yourls_is_valid_user() in includes/functions-auth.php checks for a valid user via the login 
 * form or stored cookie. The 'shunt_is_valid_user' filter allows plugins such as this one, to short-circuit
 * the entire function.
 */

/* This says: when filter 'shunt_is_valid_user' is triggered, execute function 'aaf_rapidconnect_auth'
 * and send back it's return value. Filters should always have a return value.
 */
yourls_add_filter( 'shunt_is_valid_user' , 'aaf_rapidconnect_auth' );

function aaf_rapidconnect_auth() {
    session_start();

	yourls_debug_log( "aaf_rapidconnect_auth() checking SESSION" );
	yourls_debug_log( "_SESSION[]" . print_r($_SESSION, true) );

	// Logout request
	if( isset( $_GET['action'] ) && $_GET['action'] == 'logout' ) {
		// clean up things incase the user wants to login again in the same browser session
		unset($_SESSION['jti']);

		yourls_do_action( 'logout' );
		yourls_store_cookie( null );
		aaf_rapidconnect_login_screen();
		die();
	}

	// Handle API here - will only handle the simple signature method
	// Note - this is defined by the user/config.php yourls_user_passwords array() at this point

	if
		// API only: Secure (no login or pwd) and time limited token
		// ?timestamp=12345678&signature=md5(totoblah12345678)
		( yourls_is_API() &&
		    isset( $_REQUEST['timestamp'] ) && !empty($_REQUEST['timestamp'] ) &&
		    isset( $_REQUEST['signature'] ) && !empty($_REQUEST['signature'] )
		)
	{
		yourls_do_action( 'pre_login_signature_timestamp' );
		$unfiltered_valid = yourls_check_signature_timestamp();
		return $unfiltered_valid;
	}
	elseif
		// API only: Secure (no login or pwd)
		( yourls_is_API() &&
			!isset( $_REQUEST['timestamp'] ) &&
			isset( $_REQUEST['signature'] ) && !empty( $_REQUEST['signature'] )
		)
	{
		yourls_do_action( 'pre_login_signature' );
		$unfiltered_valid = yourls_check_signature();
		return $unfiltered_valid;
	}

	$aaf_rapidconnect_key = yourls_get_option( 'aaf_rapidconnect_key' );
	$aaf_rapidconnect_auth_url = yourls_get_option( 'aaf_rapidconnect_auth_url' );
	$aaf_rapidconnect_issuer = yourls_get_option( 'aaf_rapidconnect_issuer' );
	$aaf_rapidconnect_audience = yourls_get_option( 'aaf_rapidconnect_audience' );
	$aaf_attribute_user = yourls_get_option( 'aaf_attribute_user' );

	if (isset($_SESSION['sub']) && $_SESSION['sub']) {
		// User has already authenticated against AAF, nothing to do
		// Just have to reset the username from the session data each time
		yourls_set_user($_SESSION['attributes'][$aaf_attribute_user]);
		if ( !yourls_is_API() ) {
			// Satisfy yourls' cookie generation routine
			yourls_store_cookie( YOURLS_USER );
		}
		return true;
	} else {
		if (! isset($_POST['assertion'])) {
			// Display a login screen, so the user can invoke the login process
			aaf_rapidconnect_login_screen();
			die();
		} else {
			// At this point get the JWT assertion and perform necessary validation
			require_once "JWT-PHP/JWT.php";

			$config = array();
			$config['aaf_rapidconnect'] = array(
											'iss' => $aaf_rapidconnect_issuer,
											'aud' => $aaf_rapidconnect_audience
											);
			$key = $aaf_rapidconnect_key;

			$JWT = new JWT;
			$verified_jwt = $JWT->decode($_POST['assertion'], $key);
			yourls_debug_log('about to export verified JWT');
			yourls_debug_log(var_export($verified_jwt, true));

			// have to use "true" as we need decoded as associative array
			$jwt = json_decode($verified_jwt, true);
			yourls_debug_log(var_export($jwt, true));

			$now = strtotime("now");

			// audience is correct, issuer is correct, time is not before (nbr) and not past expired
			if ( $jwt['aud'] == $config['aaf_rapidconnect']['aud'] &&
					$jwt['iss'] == $config['aaf_rapidconnect']['iss'] &&
					$now >= $jwt['nbf'] &&
					$now < $jwt['exp'] ) {
				// need to confirm this criteria
				if ( isset($_SESSION['jti']) && $jwt['jti'] != $_SESSION['jti'] ) {
					// this login has already succeeded
					yourls_e( "Login failed - session incorrect" );
					die();
				} else {
					$_SESSION['jti'] = $jwt['jti'];
				}
				$_SESSION['sub'] = $jwt['sub'];
				$_SESSION['attributes'] = $jwt['https://aaf.edu.au/attributes'];

				yourls_debug_log( "mail attribute == " . $_SESSION['attributes'][$aaf_attribute_user] );

				// At this point we want to validate the user is able to login
				// Validate against ?? (a list ? - TBC)
				// Display an error if no good
				if ( aaf_rapidconnect_check_user( $_SESSION['attributes'] ) === false ) {
					aaf_rapidconnect_access_denied( $_SESSION['attributes'] );
					die();
				}

				// get the mail attribute for the user in YOURLS
				yourls_set_user($_SESSION['attributes'][$aaf_attribute_user]);
				if ( !yourls_is_API() ) {
					// Satisfy yourls' cookie generation routine
					yourls_store_cookie( YOURLS_USER );
				}

				return true;
			} else {
				$_SESSION['sub'] = false;
				unset($_SESSION['sub']);
				unset($_SESSION['attributes']);
				yourls_e( "Login failed - criteria incorrect" );
				die();
			}
		}
    }
}

function aaf_rapidconnect_check_user( $aaf_attributes ) {
	$valid_user = false;

	yourls_debug_log( "aaf_rapidconnect_check_user() eduPersonScopedAffiliation value" . $aaf_attributes['edupersonscopedaffiliation'] );

	// More details on eduPersonScopedAffiliation - http://wiki.aaf.edu.au/tech-info/attributes/edupersonscopedaffiliation
	// If at least 1 "staff@" is found in the eduPersonScopedAffiliation attribute, this user is allowed access
	$valid_user = (count(preg_grep("/^staff@/", explode(";", $aaf_attributes['edupersonscopedaffiliation']))) > 0);

	return ( $valid_user ); 
}

// Display the access denied in a nice window
function aaf_rapidconnect_access_denied( $aaf_attributes ) {
	$aaf_attribute_user = yourls_get_option( 'aaf_attribute_user' );

	require_once( YOURLS_INC.'/functions-html.php' );

	yourls_html_head( 'access', 'Access denied' );
	yourls_html_logo();

	echo <<<HTML
	<h2>Admin access denied</h2>
	<p>You ({$aaf_attributes['cn']} - {$aaf_attributes[$aaf_attribute_user]}) are not authorised to access the admin pages of this YOURLS instance.</p>

	<p>If you believe you should have access, contact <a href="mailto:eresearch@deakin.edu.au?Subject=eresear.ch%20shorten%20URL%20service">Christopher McAvaney</a> for assistance.</p>
HTML;

	yourls_html_footer();
}

// Display simple page with an AAF Login button
function aaf_rapidconnect_login_screen() {
	$aaf_rapidconnect_auth_url = yourls_get_option( 'aaf_rapidconnect_auth_url' );

	require_once( YOURLS_INC.'/functions-html.php' );
	yourls_html_head( 'access', 'AAF Rapid Connect login' );
	yourls_html_logo();

?>
	<div id="login" style="margin-top: 100px;">
	<p class="error"><?php echo yourls__( 'Please log in' ); ?></p>
	<form action="<?php echo filter_var($aaf_rapidconnect_auth_url, FILTER_SANITIZE_URL); ?>" method="GET">
		<input type="submit" id="launch-login-button" name="launch-login-button" value="<?php yourls_e( 'AAF login' ); ?>" class="button" /></div>
	</form>
	<p><a href="http://www.aaf.edu.au"><img src="https://rapid.aaf.edu.au/aaf_service_110x26.png" /></a></p>
	</div>
<?php
	yourls_html_footer();
}

yourls_add_action( 'logout', 'aaf_rapidconnect_logout' );

function aaf_rapidconnect_logout() {
	yourls_debug_log( "aaf_rapidconnect_logout() about to unset things" );

	session_start();
	$_SESSION['sub'] = false;
	$_SESSION['attributes'] = false;
	unset($_SESSION['sub']);
	unset($_SESSION['attributes']);

	yourls_debug_log( "aaf_rapidconnect_logout() should now be logged out" );
}

// Add to the admin page
yourls_add_action( 'html_head', 'aaf_rapidconnect_headers' );

function aaf_rapidconnect_headers() {
	echo <<<HTML
	<style type="text/css">
		label {
			padding-right: 0.25rem;
			width: 10rem;
			display: inline-block;
			text-align: right;
		}
	</style>

HTML;
}

yourls_add_action( 'plugins_loaded', 'aaf_rapidconnect_add_page' );

function aaf_rapidconnect_add_page() {
	yourls_register_plugin_page( 'aaf_rapidconnect', 'AAF Rapid Connect options', 'aaf_rapidconnect_do_page' );
}

// Display the plugin page
function aaf_rapidconnect_do_page() {
	// Check if a form was submitted
	if ( isset( $_POST['aaf_rapidconnect_key'] ) ) {
		// check nonce
		yourls_verify_nonce( 'aaf_rapidconnect' );

		// process form
		yourls_update_option( 'aaf_rapidconnect_key', $_POST['aaf_rapidconnect_key'] );
		if ( isset( $_POST['aaf_rapidconnect_auth_url'] ) ) yourls_update_option( 'aaf_rapidconnect_auth_url', $_POST['aaf_rapidconnect_auth_url'] );
		if ( isset( $_POST['aaf_rapidconnect_issuer'] ) ) yourls_update_option( 'aaf_rapidconnect_issuer', $_POST['aaf_rapidconnect_issuer'] );
		if ( isset( $_POST['aaf_rapidconnect_audience'] ) ) yourls_update_option( 'aaf_rapidconnect_audience', $_POST['aaf_rapidconnect_audience'] );
		if ( isset( $_POST['aaf_attribute_user'] ) ) yourls_update_option( 'aaf_attribute_user', $_POST['aaf_attribute_user'] );
	}


	// Get values from database
	$aaf_rapidconnect_key = yourls_get_option( 'aaf_rapidconnect_key' );
	$aaf_rapidconnect_auth_url = yourls_get_option( 'aaf_rapidconnect_auth_url' );
	$aaf_rapidconnect_issuer = yourls_get_option( 'aaf_rapidconnect_issuer' );
	$aaf_rapidconnect_audience = yourls_get_option( 'aaf_rapidconnect_audience' );
	$aaf_attribute_user = yourls_get_option( 'aaf_attribute_user' );

	$nonce = yourls_create_nonce( 'aaf_rapidconnect' );
	yourls_debug_log( "aaf_rapidconnect_do_page() nonce == " . $nonce );

	// heredoc to the form
	echo <<<HTML
	<div id="wrap">
		<h2>AAF Rapid Connect options</h2>
		<form method="post" id="aaf_rapidconnect_form" name="aaf_rapidconnect_form">
			<input type="hidden" name="nonce" value="$nonce" />

			<div>
				<input type="hidden" name="aaf_rapidconnect_key" value="$aaf_rapidconnect_key" />
				<label for="aaf_rapidconnect_key" form="aaf_rapidconnect_form">Key:</label>
				<input type="text" value="$aaf_rapidconnect_key" id="aaf_rapidconnect_key" name="aaf_rapidconnect_key" size="32" />
			</div>

			<div>
				<input type="hidden" name="aaf_rapidconnect_issuer" value="$aaf_rapidconnect_issuer" />
				<label for="aaf_rapidconnect_issuer" form="aaf_rapidconnect_form">Issuer:</label>
				<input type="text" value="$aaf_rapidconnect_issuer" id="aaf_rapidconnect_issuer" name="aaf_rapidconnect_issuer" size="32" />
			</div>

			<div>
				<input type="hidden" name="aaf_rapidconnect_audience" value="$aaf_rapidconnect_audience" />
				<label for="aaf_rapidconnect_audience" form="aaf_rapidconnect_form">Audience (URL of the instance):</label>
				<input type="text" value="$aaf_rapidconnect_audience" id="aaf_rapidconnect_audience" name="aaf_rapidconnect_audience" size="32" />
			</div>

			<div>
				<input type="hidden" name="aaf_rapidconnect_auth_url" value="$aaf_rapidconnect_auth_url" />
				<label for="aaf_rapidconnect_auth_url" form="aaf_rapidconnect_form">Auth URL:</label>
				<input type="text" value="$aaf_rapidconnect_auth_url" id="aaf_rapidconnect_auth_url" name="aaf_rapidconnect_auth_url" size="72" />
			</div>

			<div>
				<input type="hidden" name="aaf_attribute_user" value="$aaf_attribute_user" />
				<label for="aaf_attribute_user" form="aaf_attribute_user">User attribute:</label>
				<input type="text" value="$aaf_attribute_user" id="aaf_attribute_user" name="aaf_attribute_user" size="32" />
			</div>

			<div>
				<input type="submit" value="Submit" />
			</div>
		</form>
	</div>
HTML;
}

?>
