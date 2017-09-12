#!/usr/bin/perl

# DNS Lookup script
# Run external command
$DNSTRAN = '/usr/local/dnstran/dnstran';



# Log results to file
$DNSFILE = '/var/db/slac_dns.db';
open DNS, "<$DNSFILE";
while (<DNS>) {
    ($dtime, $dip, $dname) = split ' ';
    $dtable{$dip} = $dname;
    print "$dtime $dip $dname\n";
    #print int(time()/60);
}
