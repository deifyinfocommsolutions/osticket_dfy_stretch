<?php
/*********************************************************************
    login.php

    Handles staff authentication/logins

    Peter Rotich <peter@osticket.com>
    Copyright (c)  2006-2013 osTicket
    http://www.osticket.com

    Released under the GNU General Public License WITHOUT ANY WARRANTY.
    See LICENSE.TXT for details.

    vim: expandtab sw=4 ts=4 sts=4:
**********************************************************************/
require_once('../main.inc.php');
if(!defined('INCLUDE_DIR')) die('Fatal Error. Kwaheri!');

// Bootstrap gettext translations. Since no one is yet logged in, use the
// system or browser default
TextDomain::configureForUser();

require_once(INCLUDE_DIR.'class.staff.php');
require_once(INCLUDE_DIR.'class.csrf.php');

$content = Page::lookupByType('banner-staff');

$dest = $_SESSION['_staff']['auth']['dest'];
$msg = $_SESSION['_staff']['auth']['msg'];
$msg = $msg ?: ($content ? $content->getLocalName() : __('Authentication Required'));
$dest=($dest && (!strstr($dest,'login.php') && !strstr($dest,'ajax.php')))?$dest:'index.php';
$show_reset = false;
if($_POST) {
//	alert(5);
    // Check the CSRF token, and ensure that future requests will have to
    // use a different CSRF token. This will help ward off both parallel and
    // serial brute force attacks, because new tokens will have to be
    // requested for each attempt.
    if (!$ost->checkCSRFToken())
        Http::response(400, __('Valid CSRF Token Required'));

    // Rotate the CSRF token (original cannot be reused)
    $ost->getCSRF()->rotate();
}
if(true) {
    // Lookup support backends for this staff
    $username = trim($_SERVER["REMOTE_USER"]);
    if ($user = StaffAuthenticationBackend::process($username,
            $_SERVER["PHP_AUTH_PW"], $errors)) {
        session_write_close();
        session_regenerate_id();
	$_SERVER["PHP_AUTH_PW"] = "";
        Http::redirect($dest);
        require_once('index.php'); //Just incase header is messed up.
        exit;
    }

    $msg = $errors['err']?$errors['err']:__('Invalid login');
    $show_reset = true;
}
elseif ($_GET['do']) {
//		alert(4);
    switch ($_GET['do']) {
    case 'ext':
        // Lookup external backend
        if ($bk = StaffAuthenticationBackend::getBackend($_GET['bk']))
            $bk->triggerAuth();
    }
    Http::redirect('login.php');
}
// Consider single sign-on authentication backends
elseif (!$thisstaff || !($thisstaff->getId() || $thisstaff->isValid())) {
//		alert(3);
//echo $thisstaff + ' ' + $thisstaff->getId();
    if (($user = StaffAuthenticationBackend::processSignOn($errors, false))
            && ($user instanceof StaffSession))
       Http::redirect($dest);
}

// Browsers shouldn't suggest saving that username/password
Http::response(422);

define("OSTSCPINC",TRUE); //Make includes happy!
include_once(INCLUDE_DIR.'staff/login.tpl.php');
?>
