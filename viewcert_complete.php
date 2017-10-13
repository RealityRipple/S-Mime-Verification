<?php

/**
  * SquirrelMail S/MIME Verification Plugin
  * Copyright (c) 2015 Walter Hoehlhubmer <walter.h@mathemainzel.info>
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

global $color, $download_link, $return_link, $certificate_complete;
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



// get certificate complete
//
sq_change_text_domain('smime');
$lines = x509_open_complete($cert);
$iter = 0;
$certificate_complete = array();
while (isset($lines[$iter]))
{
   $certificate_complete[$iter] = htmlentities($lines[$iter]);
   $iter++;
}



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
   $oTemplate->assign('certificate_complete', $certificate_complete, FALSE);
   $oTemplate->display('plugins/smime/viewcert_complete.tpl');
   $oTemplate->display('footer.tpl');
}
else
{

   // we can still use the template file - just trick
   // the one from the default template set
   //
   global $t;
   $t = array(); // no need to put config vars herein, they are already globalized

   include_once(SM_PATH . 'plugins/smime/templates/default/viewcert_complete.tpl');
   echo '</body></html>';

}


sq_change_text_domain('squirrelmail');



// -----------------------------------------------------------------------
//                              FUNCTIONS
// -----------------------------------------------------------------------



/**
  *
  */
function x509_open_complete($cert)
{
   global $cert_in_dir;
   if (substr($cert_in_dir, -1) !== '/') $cert_in_dir .= '/';

   $lines = array();
   
   if (isset($cert))
   {
      if (preg_match("/^[0-9A-Za-z\.]+$/", $cert))
      {
         $certfile = $cert_in_dir . $cert;
         if (file_exists($certfile)) 
         {
            exec("./openssl-cmds.sh --view-certificate-detailed $certfile", $lines, $retval);

            if ($retval == 0)
            {
               return $lines;
            }
            else
            {
               global $color;
               error_box("Certificate file ($cert) not readable.", $color);
               return $lines;
            }
         }
         else
         {
            global $color;
            error_box("Certificate file ($cert) not found.", $color);
            return $lines;
         }
      }
      else
      {
         global $color;
         error_box("Invalid certificate filename.", $color);
         return $lines;
      }
   }
   else
   {
      global $color;
      error_box("Certificate parameter missing.", $color);
      return $lines;
   }
}
