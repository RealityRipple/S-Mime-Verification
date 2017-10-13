<?php

/**
  * viewcert.tpl
  *
  * Template for showing S/MIME certificate details
  * for the S/MIME Verification plugin.
  *
  * The following variables are available in this template:
  *
  * string  $return_link          The URI that points back to the source message
  * string  $download_link        The URI that provides download capability
  * string  $completeview_link    The URI that provides complete view
  *                               capability
  * array   $certificate_details  An associative array where keys are
  *                               certificate details field names and values
  *                               are the associated details
  *
  * Copyright (c) 2015 Walter Hoehlhubmer <walter.h@mathemainzel.info>,
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

<table width="100%" border="0" cellspacing="0" cellpadding="2" align="center">
  <tr>
    <td bgcolor="<?php echo $color[0]; ?>">
      <b><center><?php

   echo _("Viewing S/MIME Certificate") . _(" - ")
      . '<a href="' . $return_link . '">' . _("View Message") . '</a>';

?></center></b>
    </td>
  </tr>
  <tr>
    <td align="center">
      <a href="<?php echo $download_link; ?>">
      <?php echo _("Download This As A File"); ?>
      </a>
      &nbsp;|&nbsp;
      <a href="<?php echo $completeview_link; ?>">
      <?php echo _("View This Complete"); ?>
      </a>
    </td>
  </tr>
</table>
<br />
<table width="100%" border=0 cellspacing="0" cellpadding="3">
<?php foreach ($certificate_details as $title => $value) { ?>
  <tr>
    <td valign="top" align="right" width="20%" bgcolor="<?php echo $color[4]; ?>">
       <?php echo $title; ?>
    </td>
    <td valign="top" width="80%" bgcolor="<?php echo $color[4]; ?>">
       <b><?php echo $value; ?></b>
    </td>
  </tr>
<?php } ?>
</table>

