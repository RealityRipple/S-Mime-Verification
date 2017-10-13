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



/**
  * Register this plugin with SquirrelMail
  *
  */
function squirrelmail_plugin_init_smime() 
{

   global $squirrelmail_plugin_hooks;

   // verify signed messages (SM 1.4.x)
   //
   $squirrelmail_plugin_hooks['read_body_header']['smime']
      = 'smime_header_verify';


   // verify signed messages (SM 1.5.2+)
   //
   $squirrelmail_plugin_hooks['template_construct_read_headers.tpl']['smime']
      = 'smime_header_verify';


   // configuration check
   //
   $squirrelmail_plugin_hooks['configtest']['smime']
      = 'smime_check_configuration';

}



/**
  * Verify signed messages
  *
  */
function smime_header_verify() 
{
   include_once(SM_PATH . 'plugins/smime/functions.php');
   return smime_header_verify_do();
}



/**
  * Validate that this plugin is configured correctly
  *
  * @return boolean Whether or not there was a
  *                 configuration error for this plugin.
  *
  */
function smime_check_configuration()
{
   include_once(SM_PATH . 'plugins/smime/functions.php');
   return smime_check_configuration_do();
}



/**
  * Returns info about this plugin
  *
  */
function smime_info() 
{

   return array(
                 'english_name' => 'S/MIME Verification',
                 'authors' => array(
                    'Wouter Teepe' => array(
                       'email' => 'wouter@teepe.com',
                    ),
                    'Antonio Vasconcelos' => array(
                       'email' => 'vasco@threatconn.com',
                    ),
                    'Khedron Wilk' => array(
                       'email' => 'khedron@wilk.se',
                    ),
                    'Scott Heavner' => array(
                    ),
                    'Paul Lesniewski' => array(
                       'email' => 'paul@squirrelmail.org',
                       'sm_site_username' => 'pdontthink',
                    ),
                 ),
                 'version' => '1.0',
                 'required_sm_version' => '1.1.1',
                 'requires_configuration' => 0,
                 'summary' => 'Verifies S/MIME signed messages.',
                 'details' => 'This plugin enables the viewing of S/MIME signed messages (those that are sent in the "multipart/signed" mime format).  The user is able to verify the message, the sender\'s certificate, and can view and download the certificate.',
                 'requires_source_patch' => 0,
                 'other_requirements' => 'openssl',
                 'per_version_requirements' => array(
                    '1.5.2' => array(
                       'required_plugins' => array(),
                    ),
                    '1.5.0' => array(
                       'required_plugins' => array(
                          'compatibility' => array(
                             'version' => '2.0.7',
                             'activate' => FALSE,
                          )
                       )
                    ),
                    '1.4.10' => array(
                       'required_plugins' => array(),
                    ),
                    '1.4.0' => array(
                       'required_plugins' => array(
                          'compatibility' => array(
                             'version' => '2.0.7',
                             'activate' => FALSE,
                          )
                       )
                    ),
                 ),
               );

}



/**
  * Returns version info about this plugin
  *
  */
function smime_version() 
{
   $info = smime_info();
   return $info['version'];
}



