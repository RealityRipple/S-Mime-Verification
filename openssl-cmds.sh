#!/bin/sh

# SquirrelMail S/MIME Verification Plugin
#
# Copyright (c) 2015 Walter Hoehlhubmer <walter.h@mathemainzel.info>
#
# Licensed under the GNU GPL. For full terms see the file COPYING.
#
# @package plugins
# @subpackage smime

# This is the full path to the the OpenSSL executable
# on your system.  If you don't know where it is, try
# typing "which openssl" on a command line.
#
openssl="/usr/bin/openssl"

# This is the directory (-CApath) where the root certificate
# authority (CA) certificates are kept.  You can review
# the README.vasco file for information about adding
# your own (private) CA to this directory.
#
# Instead of configuring this, you can instead choose
# to point below to a valid root certificates
# file such as the one provided with this plugin (-CAfile).
#
# It depends on the linux distribution, which one is more common.
# Knoppix, Ubuntu, ... (Debian based) use -CApath
# CentOS, Fedora, ScientificLinux, ... (Red Hat based) use -CAfile 
#
# For other distributions or BSD-Unix see in the operating system manual or
# man pages about the certificate store.
#
opensslca="-CApath /etc/ssl/certs"
#opensslca="-CAfile /usr/share/squirrelmail/plugins/smime/data/ca-bundle.crt"

if [ -x $openssl ]; then
if [ "$1" ]; then

case $1 in
  --cert-subject-email-hash)
    if [ "$2" ]; then
      tmpcert=$2
      $openssl x509 -in $tmpcert -subject -email -hash -noout
      retval=0
    else
      retval=1
    fi
    ;;

  --download-certificate)
    if [ "$2" ]; then
      certfile=$2
      $openssl x509 -in $certfile -text 2>/dev/null
      retval=$?
    else
      retval=1
    fi
    ;;

  --view-certificate)
    if [ "$2" ]; then
      certfile=$2

      $openssl x509 -in $certfile -subject -noout 2>/dev/null
      $openssl x509 -in $certfile -issuer -noout 2>/dev/null

      $openssl x509 -in $certfile -startdate -noout 2>/dev/null
      $openssl x509 -in $certfile -enddate -noout 2>/dev/null

      $openssl x509 -in $certfile -serial -noout 2>/dev/null

      $openssl x509 -in $certfile -fingerprint -md5 -noout 2>/dev/null
      $openssl x509 -in $certfile -fingerprint -sha1 -noout 2>/dev/null

      $openssl x509 -in $certfile -fingerprint -sha256 -noout 2>/dev/null

      retval=0
    else
      retval=1
    fi
    ;;

  --view-certificate-detailed)
    if [ "$2" ]; then
      certfile=$2
      $openssl x509 -in $certfile -text -noout 2>/dev/null
      retval=$?
    else
      retval=1
    fi
    ;;

  --version)
    $openssl version
    retval=$?
    ;;

  --verify-smime-msg)
    if [ "$2" -a "$3" -a "$4" ]; then
      tmpcert=$3
      tmpmsg=$2
      tmpmail=$4

      $openssl smime -verify $opensslca -in $tmpmsg 2>/dev/null >/dev/null
      retval=$?

      if [ $retval -eq 0 ]; then
        $openssl smime -verify -in $tmpmsg -signer $tmpcert -out $tmpmail 2>/dev/null
        retval=$?
      else
        if [ $retval -eq 4 ]; then
          $openssl smime -verify -in $tmpmsg -noverify -signer $tmpcert -out $tmpmail 2>/dev/null
          retval=$?

          if [ $retval -eq 0 ]; then
            retval=6
          else
            if [ $retval -eq 4 ]; then
              $openssl smime -verify -in $tmpmsg -noverify -nosigs -signer $tmpcert -out $tmpmail 2>/dev/null
              retval=$?
            fi
          fi
        fi
      fi

      if [ -s $tmpcert ]; then
        if [ -s $tmpmail ]; then
          cat $tmpmail
        fi
      else
        retval=2
      fi
    else
      retval=1
    fi
    ;;

  *)
    retval=1
esac

else
retval=1
fi
else
retval=1
fi

exit $retval
