#!/usr/bin/perl 
# $Id: upload.cgi,v 1.4 2004/08/25 12:07:52 mibl Exp $

use CGI; 

use Sys::Syslog;                          # all except setlogsock, or:
use Sys::Syslog qw(:DEFAULT setlogsock);  # default set, plus setlogsock

$SECSRCH = '/usr/local/slac/secsrch.pl';
$FWSECSRCH = '/usr/local/slac/fw1-secsrch.pl';
$upload_dir = '/var/tmp';

$query = new CGI;

slog("Remote host: " . $query->remote_host());
slog("Request method: " . $query->request_method());
slog("HTTP Headers: " . $query->http());

foreach $x ($query->http()) {
    slog($x . ': ' . $query->http($x));
}

#exit;

slog("Retrieved POST value-pairs:");
%P = $query->Vars;
#slog("%P");
foreach $p1 (keys %P) {
    slog("  $p1\: $P{$p1}");
}

$filename = $query->param("logfile"); 
slog("Filename: $filename");
$email_address = $query->param("email_address"); 
slog("Email address: $email_adddress");
$type = $query->param("type");
slog("Type: $type");

# Check for correctly filled in params befor processing

if ($filename =~ m/^$/) {
    slog("Missing filename. Exiting");
    print $query->header(-type=>'text/html');
    print $query->start_html();
    print "Missing filename!<br>Hit 'Back' in your browser and select a file before submitting.";
    print $query->end_html();
    exit;
}



$ssparam = '';   # String of parameters to send to analysis prog

if ($query->param("nr") eq '') { $ssparam .= ' -N '; }
if ($query->param('output') eq 'xml') { 
    $ssparam .= ' -X '; 
    print $query->header(-type=>'text/xml'); 
} else {
    print $query->header(-type=>'text/plain'); 
}

if ($query->param('explan') =~ m/^on$/i) {
    slog("Adding Explanatory texts");
    $ssparam .= ' -p ';
}

if ($type =~ m/^fw$/i) {
    $ANALYSIS = $FWSECSRCH;
    $ssparam .= ' -i ';
} elsif ($type =~ m/^web$/i) {
    $ANALYSIS = $SECSRCH;
    $ssparam .= ' -i '; 
} else {
    slog("Someone is fooling around with 'type' param. Exiting!");
    exit;
}
    
$filename =~ s/.*[\/\\](.*)/$1/; 
$file = $upload_dir . '/' . $$ . $filename;


# Start receiving file from client
$upload_filehandle = $query->upload("logfile"); 
open UPLOADFILE, ">$file";
binmode UPLOADFILE;
while ( <$upload_filehandle> ) { 
    print UPLOADFILE; 
    
} 

close UPLOADFILE; 

#$file = '/var/tmp/30290ex000916.log';

if ( ! -f $file ) {
    slog("Exiting. File '$file' does not exist.");
    die "Exiting. File '$file' does not exist.";
} else {
    slog("File uploaded: $file.");
}


($dev,$ino,$mode,$nlink,$uid,$gid,$rdev,$size,$atime,$mtime,$ctime,$blksize,$blocks) = stat "$file";

$run = $ANALYSIS . " $ssparam $file " . '-o -';

slog("Command to run: " . $run);

#$result = system($run);
$result = qx/$run/;

#print $query->header(-type => "text/xml"); 
#print "Content-Type: text/xml\n\n";
#$starttime = localtime();
#print $query->start_html();
#print "gyfebglk";
print $result;
#print $query->end_html();
exit;

print <<END_HTML; 

<HTML> 
    <HEAD> 
    <TITLE>Thanks!</TITLE> 
    </HEAD> 

    <BODY> 

    <P>Your file was received and will be processed shortly.</P> 
    <P>Your email address: $email_address</P> 
    <P>Your Logfile: $filename</P> 
    <P>Starttime: $starttime</P>
    <table>
    <tr><td>Parameters:</td><td>$ssparam</td></tr>
    <tr><td>Receieved bytes: </td><td>$size</td></tr>
    <tr><td>atime</td><td>$atime</td></tr>
    
    </table>

    Processing will commence immediately, and the results will be shown below.<br><br><br>

    <font "courier,sans serif">

END_HTML



$result = system($run);


print <<END_HTML2;

$result



    </font>
    </BODY> 
</HTML> 


END_HTML2




sub slog {
    setlogsock('unix');
    openlog('upload.cgi', 'cons,pid', 'local2');
    syslog('info', '%s', @_);
    closelog;
}
