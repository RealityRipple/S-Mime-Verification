<?php

/**
  * SquirrelMail S/MIME Verification Plugin
  *
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

global $data_dir, $color, $openssl, $echo, $cadir, $easycerts,
       $cert_in_dir, $row_highlite_color;



   // This is the color used in the background of the signature
   // verification information presented to the user.  $color[9]
   // may be subdued in some display themes, $color[16] will usually
   // stand out rather strongly.  You may add any color you would
   // like here, including static ones.  This information may or may
   // not be used under SquirrelMail 1.5.2+.
   //
   // $row_highlite_color = $color[9];
   // $row_highlite_color = $color[16];
   // $row_highlite_color = '#ff9933';
   //
   $row_highlite_color = $color[16];



   // This is the full path to the the OpenSSL executable
   // on your system.  If you don't know where it is, try
   // typing "which openssl" on a command line.
   // 
   $openssl = '/usr/bin/openssl';



   // This is the full path to the echo executable on your
   // system.  If you don't know where it is, try typing
   // "which echo" on a command line.
   //
   $echo = '/bin/echo';



   // This is the directory where the root certificate
   // authority (CA) certificates are kept.  You can review
   // the README.vasco file for information about adding
   // your own (private) CA to this directory.
   //
   // Instead of configuring this, you can instead choose
   // to point $easycerts below to a valid root certificates
   // file such as the one provided with this plugin.
   //
   $cadir = '/etc/ssl/certs';



   // Easy root certificate setup:
   //
   // This might conflict with the $cadir setting above; the OpenSSL
   // documentation is unclear on this point.  This has been tested
   // with both $cadir and $easycerts settings defined and no problems
   // have been reported, but this may only be the case when there is
   // nothing in the $cadir location.
   //
   // This is the full path to a file containing a set of trusted
   // root certificates.  One such file is included with this plugin
   // (see data/ca-bundle.crt).
   //
   // If you make use of the included CA bundle and find that it falls
   // out of date, you can always generate a new one yourself.  A script
   // called "mkcabundle.pl" is included in the data directory of this
   // plugin that contains instructions on how to do so.  View the
   // contents of that script to learn how to get the newest list of root
   // certificates and then how to convert them to the correct format.
   //
   // $easycerts = '-CAfile /usr/share/squirrelmail/plugins/smime/data/ca-bundle.crt';
   //
   $easycerts = '';



   // This is the directory where signer ceritificates are stored
   // for analysis.  It must be readable and writeable by the user
   // your web server runs as.  This setting's default value usually
   // does not need to be changed.
   //
   $cert_in_dir = $data_dir . 'certs-in/';



