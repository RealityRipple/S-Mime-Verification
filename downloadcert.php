<?php

/**
  * SquirrelMail S/MIME Verification Plugin
  *
  * Copyright (c) 2015 Walter Hoehlhubmer <walter.h@mathemainzel.info>
  * Copyright (c) 2005-2012 Paul Lesniewski <paul@squirrelmail.org>
  * Copyright (c) 2005 Khedron Wilk <khedron@wilk.se>
  * Copyright (c) 2004 Scott Heavner
  * Copyright (c) 2003 Antonio Vasconcelos <vasco@threatconn.com>
  * Copyright (c) 2001-2003 Wouter Teepe <wouter@teepe.com>
  *
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


include_once(SM_PATH . 'functions/mime.php');
include_once(SM_PATH . 'functions/display_messages.php');
include_once(SM_PATH . 'plugins/smime/functions.php');
global $color, $download_link, $return_link, $certificate_details;
smime_init();


sqgetGlobalVar('cert', $cert, SQ_GET);


header('Pragma: ');
header('Cache-Control: cache');

   
if (isset($cert))
{
   if (substr($cert_in_dir, -1) !== '/') $cert_in_dir .= '/';

   if (preg_match("/^[0-9A-Za-z\.]+$/", $cert))
   {
      $certfile = $cert_in_dir . $cert;
      if (file_exists($certfile))
      {
         $lines = array();
         exec("$openssl_cmds --download-certificate $certfile", $lines, $retval);

         if ($retval==0)
         {
            if (function_exists('SendDownloadHeaders'))
               SendDownloadHeaders('application', 'octet-stream', 'cert.pem', 1);
            else
               DumpHeaders('application', 'octet-stream', 'cert.pem', 1);

            $iter = 0;
            while (isset($lines[$iter]))
               echo $lines[$iter++] . "\n";
         }
         else
         {
            global $color;
            error_box("Certificate file ($cert) not readable.", $color);
         }
      }
      else
      {
         global $color;
         error_box("Certificate file ($cert) not found.", $color);
      }
   }
   else
   {
      global $color;
      error_box("Invalid certificate filename.", $color);
   }
}
else
{
   global $color;
   error_box("Certificate parameter missing.", $color);
}



   // This code is a touch old, but that doesn't matter because it is only
   // used in old versions of SquirrelMail where SendDownloadHeaders() does
   // not exist.  It was added to functions/mime.php in version 1.4.3.
   //
   // This function is verified to work with Netscape and the *very latest*
   // version of IE.  I don't know if it works with Opera, but it should now.
   function DumpHeaders($type0, $type1, $filename, $force)
   {
      global $HTTP_USER_AGENT;
      
      $isIE = 0;
      if (strstr($HTTP_USER_AGENT, 'compatible; MSIE ') !== false &&
          strstr($HTTP_USER_AGENT, 'Opera') === false) {
        $isIE = 1;
      }
      
      $filename = preg_replace('/[^-a-zA-Z0-9.]/', '_', $filename);

      // A Pox on Microsoft and it's Office!
      if (! $force)
      {
          // Try to show in browser window
          header("Content-Disposition: inline; filename=\"$filename\"");
          header("Content-Type: $type0/$type1; name=\"$filename\"");
      }
      else
      {
          // Try to pop up the "save as" box
          // IE makes this hard.  It pops up 2 save boxes, or none.
          // http://support.microsoft.com/support/kb/articles/Q238/5/88.ASP
          // But, accordint to Microsoft, it is "RFC compliant but doesn't
          // take into account some deviations that allowed within the
          // specification."  Doesn't that mean RFC non-compliant?
          // http://support.microsoft.com/support/kb/articles/Q258/4/52.ASP
          //
          // The best thing you can do for IE is to upgrade to the latest
          // version
          if ($isIE) {
             // http://support.microsoft.com/support/kb/articles/Q182/3/15.asp
             // Do not have quotes around filename, but that applied to
             // "attachment"... does it apply to inline too?
             //
             // This combination seems to work mostly.  IE 5.5 SP 1 has
             // known issues (see the Microsoft Knowledge Base)
             header("Content-Disposition: inline; filename=$filename");
             
             // This works for most types, but doesn't work with Word files
             header("Content-Type: application/download; name=\"$filename\"");

             // These are spares, just in case.  :-)
             //header("Content-Type: $type0/$type1; name=\"$filename\"");
             //header("Content-Type: application/x-msdownload; name=\"$filename\"");
             //header("Content-Type: application/octet-stream; name=\"$filename\"");
          } else {
             header("Content-Disposition: attachment; filename=\"$filename\"");
             // application/octet-stream forces download for Netscape
             header("Content-Type: application/octet-stream; name=\"$filename\"");
          }
      }
   }

