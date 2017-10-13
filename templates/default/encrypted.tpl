<?php

/**
  * encrypted.tpl
  *
  * Template for showing S/MIME signature verification
  * information for the S/MIME Verification plugin.
  *
  * The following variables are available in this template:
  *
  * string  $row_highlite_color  (Hex) Highlight background color to be used.
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
    <b><?php echo _("S/MIME Encrypted By"); ?>:</b>
  </td>
  <td class="fieldValue">
    <?php echo _("Unknown"); ?>
  </td>
</tr>
