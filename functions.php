<?php

/**
  * SquirrelMail S/MIME Verification Plugin
  *
  * Copyleft  (-) 2017 Andrew Sachen <webmaster@realityripple.com>
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


/**
  * Initialize this plugin (load config values)
  *
  * @return boolean FALSE if no configuration file could be loaded, TRUE otherwise
  *
  */
function smime_init()
{

   if (!@include_once(SM_PATH . 'config/config_smime.php'))
      if (!@include_once(SM_PATH . 'plugins/smime/config.php'))
         if (!@include_once(SM_PATH . 'plugins/smime/config_default.php'))
            return FALSE;

   return TRUE;

}



/**
  * Validate that this plugin is configured correctly
  *
  * @return boolean Whether or not there was a
  *                 configuration error for this plugin.
  *
  */
function smime_check_configuration_do()
{

   global $cert_in_dir;
   global $openssl_cmds;
   global $tmp_dir;

   // only need to do this pre-1.5.2, as 1.5.2 will make this
   // check for us automatically
   //
   if (!check_sm_version(1, 5, 2))
   {

      // if running 1.4.10+ (but not 1.5.0 or 1.5.1)
      // this test does not need to be performed
      //
      if (check_sm_version(1, 4, 10) && !check_sm_version(1, 5, 0))
      { /* no-op */ }


      // otherwise, try to find Compatibility, and
      // then that it is v2.0.7+
      //
      else
      {
         if (function_exists('check_plugin_version')
          && check_plugin_version('compatibility', 2, 0, 7, TRUE))
         { /* no-op */ }


         // something went wrong
         //
         else
         {
            do_err('S/MIME Verification plugin requires the Compatibility plugin version 2.0.7+', FALSE);
            return TRUE;
         }
      }

   }

   // make sure plugin is correctly configured
   //
   if (!smime_init())
   {
      do_err('S/MIME Verification plugin is missing its main configuration file', FALSE);
      return TRUE;
   }

   // check for openssl
   //
   $res = exec("$openssl_cmds --version", $output, $retval);
   if ($retval)
   {
      do_err('S/MIME Verification plugin had a problem executing the openssl program at ./openssl-cmds.sh: ' . $res, FALSE);
      return TRUE;
   }
   if (preg_match("/^OpenSSL.*1\.0\.[1-9]/", $res) == 0)
   {
      do_err('S/MIME Verfication plugin requires a newer release of openssl, actual release: ' . $res . '.', FALSE);
      return TRUE;
   }

   // check that the cert scratch directory is readable/writable
   //
   smime_working_directory_init();
   if (!is_dir($cert_in_dir) || !is_readable($cert_in_dir) || !is_writable($cert_in_dir))
   {
      do_err('S/MIME Verification plugin certificates working directory ($cert_in_dir) is not properly configured (' . $cert_in_dir . ')', FALSE);
      return TRUE;
   }

   // check that the temporary directory is readable/writeable
   if (!is_dir($tmp_dir) || !is_readable($tmp_dir) || !is_writable($tmp_dir))
   {
      do_err('S/MIME Verification plugin temporary directory ($tmp_dir) is not properly configured (' . $tmp_dir . ')', FALSE);
      return TRUE;
   }

   return FALSE;

}


/**
  * Verify the signature on a signed message
  *
  * @param string The full message being verified
  * @param string The sender/from address for the message if available
  *
  * @return array A list of the OpenSSL verification result value,
  *               the full command output, the name of the sender,
  *               and the certificate
  *
  */
function verify_smime($message_in, $sender_address='')
{

   global $message, $cert_in_dir;
   global $openssl_cmds;
   global $tmp_dir;

   if (substr($cert_in_dir, -1) !== '/') $cert_in_dir .= '/';
   if (substr($tmp_dir, -1) !== '/') $tmp_dir .= '/';

   smime_init();

   $tmpmsg = tempnam($tmp_dir, 'msg0');
   $fd = fopen($tmpmsg, "w");
   if ($fd)
   {
      $len = fwrite($fd, $message_in);
      fclose($fd);
      chmod($tmpmsg, 0600);
   }

   $tmpcert = tempnam($tmp_dir, 'cert0');
   touch($tmpcert);
   chmod($tmpcert, 0600);
   
   $tmpmail = tempnam($tmp_dir, 'mail0');
   touch($tmpmail);
   chmod($tmpmail, 0600);

   $cert = '';

   exec("$openssl_cmds --verify-smime-msg $tmpmsg $tmpcert $tmpmail 2>/dev/null", $message_out, $retval);

   if (($retval == 0) || ($retval == 4) || ($retval == 6))
   {
      $hash = exec("$openssl_cmds --cert-subject-email-hash $tmpcert", $lines);

      // get email - use sender's address if it's in the certificate,
      // otherwise just take the first one we can find
      if (in_array($sender_address, $lines))
         $email = $sender_address;
      else if (!empty($lines[1]))
         $email = $lines[1];
      else
         $email = '';

      // get name
      preg_match("/\/CN=(.+?)(\/|$)/", $lines[0], $matches);

      if (empty($matches[1])) $matches[1] = '';

      $name = htmlentities($matches[1] . ' <' . $email . '>');

      $dontcopy = false;
      $longcert = $cert_in_dir . $hash . '.O';
      if (file_exists($longcert))
      {
      /*
       * following file compare takes more time, ... 
       *
         $equal = false;
         if (filesize($longcert) == filesize($tmpcert))
         {
            $fd1 = fopen($longcert, 'r');
            $fd2 = fopen($tmpcert, 'r');
            do
            {
               $buf1 = fgets($fd1, 1024);
               $buf2 = fgets($fd2, 1024);
               $equal = ($buf1 == $buf2);
            }
            while ($equal && !feof($fd1)); //  && !feof($fd2))
            fclose($fd1);
            fclose($fd2);
         }
       *
       * ... than just comparing md5-hashes ...
       * (sha1 would be better, but not neccessary)
       */
         $md5a = md5_file($longcert);
         $md5b = md5_file($tmpcert);

         if ($md5a == $md5b) //  if ($equal)
         {
            unlink($tmpcert);
            $dontcopy = true;
         }
         else
         {
            $longcert = tempnam($cert_in_dir, $hash . '.O');
         }
      }
      if ($dontcopy == false)
      {
         copy($tmpcert, $longcert);
         unlink($tmpcert);
      }

      $tmpcert = $longcert;

      preg_match("/.*\/(.*)/", $tmpcert, $res);
      $cert = $res[1];
   }
   else
   {
      unlink($tmpcert);
   }
   $message_out = implode("\r\n", $message_out);

   unlink($tmpmsg);
   unlink($tmpmail);

   return array($retval, $message_out, $name, $cert);
}



/**
  * Converts the results of the verification process
  * to displayable text
  *
  * @param int The verification code
  *
  * @return string The displayable explanation of the code
  *
  */
function convert_verify_result_to_displayable_text($retval)
{

   sq_change_text_domain('smime');
   switch ($retval)
   {
      case 0: $str = _("verified"); break;
      case 1: $str = _("error 1; please send bug report"); break;
      case 2: $str = _("message signature invalid"); break;
      case 3: $str = _("message format error"); break;
      case 4: $str = _("message has been altered"); break;
      case 5: $str = _("message has not been altered, but could not verify due to wrong system setup"); break;
      case 6: $str = _("not verified"); break;
   }
   sq_change_text_domain('squirrelmail');

   return $str;

}



/**
  * Gets full message body of desired message
  *
  * @param resource An IMAP server connection handle
  * @param string   The UID of the desired message
  *
  * @return string the message, or an error message if an error occurs
  *
  */
function mime_fetch_full_body ($imap_stream, $id)
{

   global $uid_support;
  
   $cmd = "UID FETCH $id BODY.PEEK[]";
   $data = sqimap_run_command($imap_stream, $cmd, true, $response, $message, $uid_support);
   $topline = array_shift($data);

   while (! preg_match('/\\* [0-9]+ FETCH /', $topline) && $data)
      $topline = array_shift($data);

   $wholemessage = implode('', $data);
   if (preg_match('/\\{([^\\}]*)\\}/', $topline, $regs))
   {
      return substr($wholemessage, 0, $regs[1]);
   }
   else if (preg_match('/"([^"]*)"/', $topline, $regs))
   {
      return $regs[1];
   }

   $str = 'Body retrival error. Please report this bug!' . "\n";
   $str .= 'Response:' . $response . "\n";
   $str .= 'Message:' . $message . "\n";
   $str .= 'FETCH line:' . $topline;
   $str .= "---------------\n$wholemessage";
   foreach ($data as $d)
   {
      $str .= htmlspecialchars($d) . "\n";
   }

   return $str;
}



/**
  * Determine what parts of the message are signed
  *
  * @param string Message body
  * 
  * @return string The parts of the message that are signed (displayable)
  *
  */
function signed_parts($body)
{

   sq_change_text_domain('smime');
   $ret = '';

   if (preg_match("/(^.*^Content-Type:.*)\r\n\r\n/smUi", $body, $regs))
   {
      if (preg_match("/^Content-Type: *multipart\/mixed/mi", $regs[1]))
      {
         $red = "Body: \r\nAttachments: \r\n" . $regs[1];
      }
      else
      {
         $red = "Body: \r\n" . $regs[1];
      }
      $red = preg_replace("/^Content-.*$/mi", '', $red);
      preg_match_all("/^(.*):/mU", $red, $matches);
      $parts = $matches[1];
      foreach($parts as $partname)
      {
         switch ($partname)
         {
            case 'Body':        $parts[key($parts)] = _("Body"); break;
            case 'Attachments': $parts[key($parts)] = _("Attachments"); break;
         }
         next($parts);
      }
      $ret = implode(_(", "), $parts);
   }
   else
   {
      $ret = _("Body");
   }

   sq_change_text_domain('squirrelmail');
   return $ret;

}



/**
  * Verify signed messages
  *
  */
function smime_header_verify_do()
{

   global $imapConnection, $passed_id, $color, $message,
          $mailbox, $where, $what, $startMessage, $uid_support,
          $row_highlite_color;

   smime_working_directory_init();

   // grab the sender address
   // (AddressStructure class stupidly has no way to get just the email address)
   $sender_address = '';
   if (!empty($message->rfc822_header->from[0]->mailbox))
      $sender_address = (!empty($message->rfc822_header->from[0]->host)
                      ? $message->rfc822_header->from[0]->mailbox
                        . '@' . $message->rfc822_header->from[0]->host
                      : $message->rfc822_header->from[0]->mailbox);


   if ($message->header->type0 == 'application' &&
       strpos($message->header->type1, 'pkcs7-mime') !== FALSE)
   {

      sq_change_text_domain('smime');

      // Output for SM 1.5.2+
      if (check_sm_version(1, 5, 2))
      {
         global $oTemplate;
         $oTemplate->assign('row_highlite_color', $row_highlite_color);
         $output = $oTemplate->fetch('plugins/smime/encrypted.tpl');
         return array('read_body_header' => $output);
      }
      else
      //
      // Output for SM 1.4.x
      {

         echo "      <tr bgcolor=\"" . $row_highlite_color . "\">\n"
            . "        <td width=\"20%\" align=\"right\" valign=\"top\">\n<b>"
            . _("S/MIME Encrypted By:")
            . "        </b></td><td width=\"80%\" valign=\"top\">\n"
            . _("Unknown")
            . "        </td>\n"
            . "      </tr>\n";

      }

      sq_change_text_domain('squirrelmail');

   }      

   if ($message->header->type0 == 'multipart' and $message->header->type1 == 'signed')
   {
      $cmd = "UID FETCH $passed_id BODY.PEEK[HEADER.FIELDS (Content-Type)]";
      $read = sqimap_run_command($imapConnection, $cmd, true, $response, $mess, $uid_support);

      if (preg_match('/protocol=(")?application\/(x-)?pkcs7-signature(")?/i', implode('', $read)))
      {

         // we have a detached s/mime message
         //
         // we remove the MIME signature entity from the message here
         // so that SquirrelMail does not try to present it to the user
         //
         // previously array_pop was done unconditionally to remove the
         // signature entity, but SM was then popping off one entity
         // every time the message was viewed, which is wrong.
         // instead, loop through entities and remove just the signature part
         //
         $entity_index_to_unset = -1;
         foreach ($message->entities as $i => $entity)
         {
            if (is_object($entity)
             && strtolower(get_class($entity)) == 'message'
             && $entity->type0 == 'application'
             && strpos($entity->type1, 'pkcs7-signature') !== FALSE)
            {
               $entity_index_to_unset = $i;
               break;
            }
         }
         if ($entity_index_to_unset > -1)
            unset($message->entities[$entity_index_to_unset]);


         $body = mime_fetch_full_body ($imapConnection, $passed_id);
         list ($retval, $lines, $name, $cert) = verify_smime($body, $sender_address);

         if ($retval == 2) $name = 'Unknown';

         $verify_status = convert_verify_result_to_displayable_text($retval);

         $signed_parts = signed_parts($lines);

         sq_change_text_domain('smime');


         // build links
         //
         $download_link = sqm_baseuri() . 'plugins/smime/downloadcert.php?cert=' . $cert;
         if ($where && $what)
            $view_link = sqm_baseuri() . 'plugins/smime/viewcert.php?mailbox=' . urlencode($mailbox) . "&passed_id=$passed_id&where=" . urlencode($where) . "&what=" . urlencode($what) . "&cert=" . $cert;
         else
            $view_link = sqm_baseuri() . 'plugins/smime/viewcert.php?mailbox=' . urlencode($mailbox) . "&passed_id=$passed_id&startMessage=$startMessage&show_more=0&cert=" . $cert;


         $tworows = ($retval == 0 || $retval == 6);

         if ($tworows || $retval == 4)
         {
            if (check_sm_version(1, 5, 2))
            {
               $view_tag = create_hyperlink($view_link, _("View Certificate"));
               $download_tag = create_hyperlink($download_link, _("Download Certificate"));
            }
            else
            {
               $view_tag = '<a href="' . $view_link . '">' . _("View Certificate") . '</a>';
               $download_tag = '<a href="' . $download_link . '">' . _("Download Certificate") . '</a>';
            }
         }
         else
         {
            $view_tag = '';
            $downloadtag = '';
         }


         if ($retval == 0)
            $signer_verified = TRUE;
         else
            $signer_verified = FALSE;



         // Output for SM 1.5.2+
         if (check_sm_version(1, 5, 2))
         {
            global $oTemplate;
            $oTemplate->assign('row_highlite_color', $row_highlite_color);
            $oTemplate->assign('signer_verified', $signer_verified);
            $oTemplate->assign('signer', $name . _(", ") . $verify_status, FALSE);
            $oTemplate->assign('view_tag', $view_tag, FALSE);
            $oTemplate->assign('download_tag', $download_tag, FALSE);
            if ($tworows)
               $oTemplate->assign('signed_parts', $signed_parts);
            else
               $oTemplate->assign('signed_parts', '');
            $output = $oTemplate->fetch('plugins/smime/signed.tpl');
            return array('read_body_header' => $output);
         }
         else
         //
         // Output for SM 1.4.x
         {

            $colortag1 = '';
            $colortag2 = '';
            if (!$signer_verified)
            {
               $colortag1 = "<font color=\"$color[2]\"><b>";
               $colortag2 = '</b></font>';
            }

            echo "      <tr bgcolor=\"$row_highlite_color\">\n"
               . "        <td width=\"20%\" align=\"right\" valign=\"top\">\n<b>"
               . _("S/MIME Signed By:")
               . "        </b></td><td width=\"80%\" valign=\"top\">\n"
               . "          <table width=\"100%\" cellpadding=\"0\" cellspacing=\"0\" border=\"0\">\n"
               . "            <tr>\n"
               . "              <td valign=\"top\" align=\"left\">\n"
               . "                $colortag1 $name" . _(", ") . "$verify_status$colortag2\n"
               . "              </td>\n"
               . "              <td valign=\"top\" align=\"right\" nowrap><small>\n"
               . "                $view_tag\n";

            if (!$tworows)
               echo "<br />\n     $download_tag\n";

            echo "                </small></td>\n"
               . "            </tr>\n"
               . "          </table>\n"
               . "        </td>\n"
               . "      </tr>\n";


            if ($tworows)
            {
               echo "      <tr bgcolor=\"$row_highlite_color\">\n"
                  . "         <td width=\"15%\" align=\"right\" valign=\"top\"><b>\n"
                  . _("Signed Parts:")
                  . "         </b></td><td width=\"85%\" valign=\"top\">\n"
                  . "            <table width=\"100%\" cellpadding=\"0\" cellspacing=\"0\" border=\"0\">\n"
                  . "              <tr>\n"
                  . "                <td valign=\"top\" align=\"left\">\n"
                  . "                  $signed_parts\n"
                  . "               </td>\n"
                  . "               <td valign=\"top\" align=\"right\" nowrap><small>\n"
                  . "                 $download_tag\n"
                  . "               </small></td>\n"
                  . "            </tr>\n"
                  . "          </table>\n"
                  . "        </td>\n"
                  . "      </tr>\n";

            }

         }

         sq_change_text_domain('squirrelmail');

      }

   }

}



/**
  * Try to make sure the certificates scratch directory is usable
  *
  */
/**
  * Try to make sure the messages scratch directory is usable
  * 
  */
function smime_working_directory_init()
{

   global $cert_in_dir;
   global $tmp_dir;

   smime_init();

   $oldmask = umask(077);

   if (!is_dir($cert_in_dir))
   {
      mkdir($cert_in_dir, 01700);
   }

   if (!is_dir($tmp_dir))
   {
      mkdir($tmp_dir, 01700);
   }

   umask($oldmask);
}
