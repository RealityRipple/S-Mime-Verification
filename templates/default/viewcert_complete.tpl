<?php

/**
  * viewcert_complete.tpl
  *
  * Template for showing S/MIME certificate details complete
  * for the S/MIME Verification plugin.
  *
  * The following variables are available in this template:
  *
  * string  $return_link          The URI that points back to the source message
  * string  $download_link        The URI that provides download capability
  * array   $certificate_complete An array with the complete certificate
  *                               details
  *
  * Copyright (c) 2015 Walter Hoehlhubmer <walter.h@mathemainzel.info>,
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

   echo _("Viewing S/MIME Certificate Complete") . _(" - ")
      . '<a href="' . $return_link . '">' . _("View Message") . '</a>';

?></center></b>
    </td>
  </tr>
  <tr>
    <td align="center">
      <a href="<?php echo $download_link; ?>">
      <?php echo _("Download This As A File"); ?>
      </a>
    </td>
  </tr>
</table>
<br />
<table width="100%" border=0 cellspacing="0" cellpadding="3">
<tr>
<td valign="top" align="left" width="100%" bgcolor="<?php echo $color[4]; ?>">
<pre>
<?php foreach ($certificate_complete as $line) { ?>
   <?php echo $line . "\n"; ?>
<?php } ?>
</pre>
</td>
</tr>
</table>

