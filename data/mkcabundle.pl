#!/usr/bin/perl -w
#
# Slightly modified version of Joe Orton's mkcabundle.pl, which
# is intended to convert Mozilla's certdata.txt file to a format
# usable with openssl as used by the SquirrelMail S/MIME
# Verification plugin.  The original script can be found here:
# http://unspecific.com/ssl/mkcabundle.pl
#
# Used to regenerate ca-bundle.crt from the Mozilla certdata.txt.
# Written by: Joe Orton and sent to modssl_users
#
# 1) Obtain Mozilla (or other) root certificate data, usually
#    certdata.txt from:
#    http://mxr.mozilla.org/mozilla/source/security/nss/lib/ckfw/builtins/certdata.txt?raw=1
#
# 2) If not already named "certdata.txt", rename it as such
#    and place it in the same directory as this script
#
# 3) Run as ./mkcabundle.pl > ca-bundle.crt
#
# 4) Delete certdata.txt
#

my $certdata = 'certdata.txt';

open(IN, $certdata) || die("Could not find or open \"$certdata\"\n");

my $incert = 0;

my ($day, $mon, $year) = (localtime(time))[3, 4, 5];
$mon += 1;
$year += 1900;

print<<EOH;
# This is a bundle of X.509 certificates of public Certificate
# Authorities.  It was generated from the Mozilla root CA list
# on $year/$mon/$day.
#
EOH

while (<IN>) {
    if (/^CKA_VALUE MULTILINE_OCTAL/) {
        $incert = 1;
        open(OUT, "|openssl x509 -text -inform DER -fingerprint")
            || die "could not pipe to openssl x509";
    } elsif (/^END/ && $incert) {
        close(OUT);
        $incert = 0;
        print "\n\n";
    } elsif ($incert) {
        my @bs = split(/\\/);
        foreach my $b (@bs) {
            chomp $b;
            printf(OUT "%c", oct($b)) unless $b eq '';
        }
    } elsif (/^CVS_ID.*Revision: ([^ ]*).*/) {
        print "# Generated from certdata.txt RCS revision $1\n#\n";
    }
}


