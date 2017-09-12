#!/usr/bin/perl

#use Apache::ParseLog;
#$base = new Apache::ParseLog();
#$transferlog = $base->getTransferLog("/home/mibl/www.gildea.com/access_log.11");
#%dailytransferredbytes = $transferlog->bytebydate();

use Parse::AccessLogEntry;
my $P = Parse::AccessLogEntry::new();
open FILE, "< $ARGV[0]";

while (<FILE>) {
    print;
    my $Hashref=$P->parse("$_");
    print "$Hashref->{host}    
    $Hashref->{user}   
    $Hashref->{date}   
    $Hashref->{time}    
    $Hashref->{diffgmt} 
    $Hashref->{rtype}   
    $Hashref->{file}    
    $Hashref->{proto}   
    $Hashref->{code}    
    $Hashref->{bytes}   
    $Hashref->{refer}   
    $Hashref->{agent}";
}
