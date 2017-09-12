#!/bin/bash -x 
# $Header: /home/mibl/Dev/slac/RCS/pub.sh,v 1.1 2007/08/27 13:21:36 mibl Exp mibl $ $Revision: 1.1 $

cp mail_parse.pl /usr/local/slac/
cp secsrch.pl /usr/local/slac/
sudo cp upload.cgi /var/wwwtornado/cgi-bin/upload.cgi
sudo cp upload2.cgi /var/wwwtornado/cgi-bin/
sudo cp progressbar.cgi /var/wwwtornado/cgi-bin/
sudo chmod +x /var/wwwtornado/cgi-bin/progressbar.cgi
sudo chown nobody.nobody /var/wwwtornado/cgi-bin/progressbar.cgi
sudo chown nobody.nobody /var/wwwtornado/cgi-bin/upload.cgi
sudo cp /home/mibl/Dev/fw1-secsrch/fw1-secsrch.pl /usr/local/slac
