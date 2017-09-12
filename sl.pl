#!/usr/bin/perl

use Sys::Syslog;       
openlog('test', 'cons,pid', 'local2:');
$msg = '%h %i';
print "$msg\n";
syslog('info', $msg);
