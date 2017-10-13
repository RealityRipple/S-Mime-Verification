<?php

/**
  * signed.tpl
  *
  * Template for showing S/MIME signature verification
  * information for the S/MIME Verification plugin.
  *
  * The following variables are available in this template:
  *
  * string  $signer              The name and verification status of the signer
  * string  $signed_parts        The parts of the message that are signed (may
  *                              be empty if not known/not applicable)
  * boolean $signer_verified     Whether or not the signer is verified
  * string  $row_highlite_color  (Hex) Highlight background color to be used.
  * string  $view_tag            The link tag for viewing the certificate details
  * string  $download_tag        The link tag for downloading of the certificate
  *
  * Copyright (c) 2008-2012 Paul Lesniewski <paul@squirrelmail.org>,
  * Licensed under the GNU GPL. For full terms see the file COPYING.
  *
  * @package plugins
  * @subpackage smime
  *
  */


// retrieve the template vars
//
extract($t);


?>

<tr id="smime" bgcolor="<?php echo $row_highlite_color; ?>">
  <td class="fieldName">
    <b><?php echo _("S/MIME Signed By"); ?>:</b>
  </td>
  <td align="left" valign="top">
    <table width="100%" border="0" cellpadding="0" cellspacing="0">
      <tr>
        <td align="left" valign="top" class="<?php if ($signer_verified) echo 'fieldValue'; else echo 'error_header'; ?>">
          <?php echo $signer; ?>
        </td>
        <td valign="top" align="right" nowrap>
          <small><?php echo $view_tag; if (empty($signed_parts)) echo '<br />' . $download_tag; ?></small>
        </td>
      </tr>
    </table>
  </td>
</tr>
<?php if (!empty($signed_parts)) { ?>
<tr id="smime" bgcolor="<?php echo $row_highlite_color; ?>">
  <td class="fieldName">
    <b><?php echo _("Signed Parts"); ?>:</b>
  </td>
  <td align="left" valign="top">
    <table width="100%" border="0" cellpadding="0" cellspacing="0">
      <tr>
        <td align="left" valign="top" class="fieldValue">
          <?php echo $signed_parts; ?>
        </td>
        <td valign="top" align="right" nowrap>
          <small><?php echo $download_tag; ?></small>
        </td>
      </tr>
    </table>
  </td>
</tr>
<?php } ?>
