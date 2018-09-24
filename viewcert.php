<?php

/**
  * SquirrelMail S/MIME Verification Plugin
  * Copyleft  (-) 2018 Andrew Sachen <webmaster@realityripple.com>
  * Copyright (c) 2015 Walter Hoehlhubmer <walter.h@mathemainzel.info>
  * Copyright (c) 2001-2003 Wouter Teepe <wouter@teepe.com>,
  * Copyright (c) 2003 Antonio Vasconcelos <vasco@threatconn.com>,
  * Copyright (c) 2004 Scott Heavner,
  * Copyright (c) 2005-2008 Paul Lesniewski <paul@squirrelmail.org>,
  * Copyright (c) 2005 Khedron Wilk <khedron@wilk.se>,
  * Licensed under the GNU GPL. For full terms see the file COPYING.
  *
  * @package plugins
  * @subpackage smime
  *
  */



// This is the bug_report options page
//
define('PAGE_NAME', 'smime_view_certificate');


// set up SquirrelMail environment
//
if (file_exists('../../include/init.php'))
   include_once('../../include/init.php');
else if (file_exists('../../include/validate.php'))
{
   define('SM_PATH', '../../');
   include_once(SM_PATH . 'include/validate.php');
}
else
{
   chdir('..');
   define('SM_PATH', '../');
   include_once(SM_PATH . 'src/validate.php');
}


// Make sure plugin is activated!
//
global $plugins;
if (!in_array('smime', $plugins))
   exit;


include_once(SM_PATH . 'functions/display_messages.php');

include_once(SM_PATH . 'plugins/smime/functions.php');

global $color, $download_link, $completeview_link, $return_link, $certificate_details;
smime_init();


sqgetGlobalVar('cert', $cert, SQ_GET);
sqgetGlobalVar('mailbox', $mailbox, SQ_GET);
sqgetGlobalVar('passed_id', $passed_id, SQ_GET);
sqgetGlobalVar('startMessage', $startMessage, SQ_GET);
sqgetGlobalVar('show_more', $show_more, SQ_GET);


// calculate return link
//
if (isset($where) && isset($what))
   $return_link = sqm_baseuri() . 'src/read_body.php?mailbox=' . urlencode($mailbox) . "&passed_id=$passed_id&where=" . urlencode($where) . '&what=' . urlencode($what);
else   
   $return_link = sqm_baseuri() . 'src/read_body.php?mailbox=' . urlencode($mailbox) . "&passed_id=$passed_id&startMessage=$startMessage&show_more=0";



// calculate download link
//
$download_link = sqm_baseuri() . 'plugins/smime/downloadcert.php?cert=' . $cert;

// calculate complete view link
//
if (isset($where) && isset($what))
   $completeview_link = sqm_baseuri() . 'plugins/smime/viewcert_complete.php?mailbox=' . urlencode($mailbox) . "&passed_id=$passed_id&where=" . urlencode($where) . "&what=" . urlencode($what) . "&cert=" . $cert;
else   
   $completeview_link = sqm_baseuri() . 'plugins/smime/viewcert_complete.php?mailbox=' . urlencode($mailbox) . "&passed_id=$passed_id&startMessage=$startMessage&show_more=0&cert=" . $cert;



// get certificate detail fields
//
sq_change_text_domain('smime');
list($owner, $issuer, $valid_from, $valid_thru, $serial, $fingerprintMD5, $fingerprintSHA1, $fingerprintSHA256) = x509_open($cert);
$certificate_details = array(
   _("Owner:")            => nl2br(htmlentities($owner)),
   _("Issuer:")           => nl2br(htmlentities($issuer)),
   _("Valid From:")       => nl2br(htmlentities($valid_from)),
   _("Valid Through:")    => nl2br(htmlentities($valid_thru)),
   _("Serial:")           => nl2br(htmlentities($serial)),
   _("MD5 Fingerprint:")  => nl2br(htmlentities($fingerprintMD5)),
   _("SHA1 Fingerprint:") => nl2br(htmlentities($fingerprintSHA1)),
   _("SHA256 Fingerprint:") => nl2br(htmlentities($fingerprintSHA256)),
);



// -----------------------------------------------------------------------
//                              INTERFACE
// -----------------------------------------------------------------------



sq_change_text_domain('squirrelmail');
displayPageHeader($color, '');
sq_change_text_domain('smime');


if (check_sm_version(1, 5, 2))
{        
   global $oTemplate;
   $oTemplate->assign('color', $color);
   $oTemplate->assign('return_link', $return_link);
   $oTemplate->assign('download_link', $download_link);
   $oTemplate->assign('completeview_link', $completeview_link);
   $oTemplate->assign('certificate_details', $certificate_details, FALSE);
   $oTemplate->display('plugins/smime/viewcert.tpl');
   $oTemplate->display('footer.tpl');
}
else
{

   // we can still use the template file - just trick
   // the one from the default template set
   //
   global $t;
   $t = array(); // no need to put config vars herein, they are already globalized

   include_once(SM_PATH . 'plugins/smime/templates/default/viewcert.tpl');
   echo '</body></html>';

}


sq_change_text_domain('squirrelmail');



// -----------------------------------------------------------------------
//                              FUNCTIONS
// -----------------------------------------------------------------------



/**
  *
  */
function x509_match($a, $b)
{
   $len = strlen($b);
   $a = trim($a);
   if (substr($a, 0, $len) == $b)
      return trim(substr($a, $len));
   else
      return '';
}



/**
  *
  */
function x509_split($a, $b, $c)
{
   $res = '';
   $lines = preg_split("/\/\w*=/", $a, -1, PREG_SPLIT_NO_EMPTY);
   for ($i = 0; $i < count($lines); $i++)
      $res = $b . $lines[$i] . $c . $res;
   return $res;
}


/**
  *
  */
function x509_open($cert)
{
   global $cert_in_dir;
   if (substr($cert_in_dir, -1) !== '/') $cert_in_dir .= '/';

   $invldcert = array("n/a", "n/a", "n/a", "n/a", "n/a", "n/a", "n/a", "n/a");

   if (isset($cert))
   {
      if (preg_match("/^[0-9A-Za-z\.]+$/", $cert))
      {
         $certfile = $cert_in_dir . $cert;
         if (file_exists($certfile)) 
         {
            $lines = array();
            exec("./openssl-cmds.sh --view-certificate $certfile 2>/dev/null", $lines, $retval);

            if (($retval == 0) &&
               $lines[0] && $lines[1] && $lines[2] && $lines[3] &&
               $lines[4] && $lines[5] && $lines[6] && $lines[7])
            {
               return array(
                  x509_split(x509_match($lines[0], "subject="), "", "\n"),
                  x509_split(x509_match($lines[1], "issuer="), "", "\n"),
                  x509_match($lines[2], "notBefore="),
                  x509_match($lines[3], "notAfter="),
                  substr(preg_replace('/(..)/', ':$1',
                     x509_match($lines[4], "serial=")),1),
                     x509_match($lines[5], "MD5 Fingerprint="),
                     x509_match($lines[6], "SHA1 Fingerprint="),
                     x509_match($lines[7], "SHA256 Fingerprint=")
               );		// MD5, SHA1 and SHA256 fingerprint
            }
            else
            {
               global $color;
               error_box("Certificate file ($cert) not readable.", $color);
               return $invldcert;
            }
         }
         else
         {
            global $color;
            error_box("Certificate file ($cert) not found.", $color);
            return $invldcert;
         }
      }
      else
      {
         global $color;
         error_box("Invalid certificate filename.", $color);
         return $invldcert;
      }
   }
   else
   {
      global $color;
      error_box("Certificate parameter missing.", $color);
      return $invldcert;
   }
}
