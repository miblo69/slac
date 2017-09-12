#!/usr/bin/perl 
# $Id: upload2.cgi,v 1.2 2004/08/27 08:35:28 mibl Exp mibl $

# This version redirects the user to a statuspage, where the results will be
# displayed instead.
# This is to accomodate for long timeouts during analysis, which 
# the httpd daemon doesn't handle well.

 
use CGI; 

use Sys::Syslog;                          # all except setlogsock, or:
use Sys::Syslog qw(:DEFAULT setlogsock);  # default set, plus setlogsock
use Fcntl ':flock'; # import LOCK_* constants

$SECSRCH = '/usr/local/slac/secsrch.pl';
$FWSECSRCH = '/usr/local/slac/fw1-secsrch.pl';
$upload_dir = '/var/tmp';

$query = new CGI;

slog("Remote host: " . $query->remote_host());
slog("Request method: " . $query->request_method());
slog("HTTP Headers: " . $query->http());

slog("Returned HTTP-Query:");
foreach $x ($query->http()) {
    slog("  " . $x . ': ' . $query->http($x));
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

$filename =~ s/.*[\/\\](.*)/$1/; 
$file = $upload_dir . '/' . $$ . $filename;

$ssparam = '';   # String of parameters to send to analysis prog

print $query->redirect('http://www.tornado.se/slac/slacupload2.htm');

if ($query->param("nr") eq '') { $ssparam .= ' -N '; }
if ($query->param('output') eq 'xml') { 
    slog("Assuming XML output");
    $ssparam .= ' -X '; 
    print $query->header(-type=>'text/xml'); 
} else {
    slog("Assuming text output");
    #$dispos = 'attachment; filename=' . $filename . '.slac.txt';
    $dispos = 'filename=' . $filename . '.slac.txt';
    #print $query->header(-type=>'text/plain');
    print $query->header(-type=>'text/html');
    #print $query->start_html();
    
    #-Content_Disposition=>$dispos); 
}

$uploadid = $query->param('UploadID');
if (sanitize($uploadid) ne 0) {
    slog("Invalid characters found in UploadID: $uploadid. Exiting.");
    die "Manipulation of UploadID detected. Aborted.";
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
    $ssparam .= " -I $uploadid -i "; 
} else {
    slog("Someone is fooling around with 'type' param. Exiting!");
    exit;
}
    

#######   Start receiving file from client
slog("Started Receiving file: $filename"); 
$statfile = "/var/tmp/$uploadid.log";
slog("Next line will execute query->upload");
$upload_filehandle = $query->upload("logfile"); 
if (!$upload_filehandle && $query->cgi_error) {
    slog("CGI Error during uload.");
    print $query->header(-status=>$query->cgi_error);
    exit 0;
}

slog("query->upload finished. Starting reading from filehandle");
open UPLOADFILE, ">$file";
binmode UPLOADFILE;
while ( <$upload_filehandle> ) { 
    print UPLOADFILE; 
    #slog("  Input Length: " . length());
    $total_recv += length(); 

    # Write progress to status file, for reading from 'progressbar.cgi'
    pstatus($filename,$total_recv,"Receiving file...");
} 

close UPLOADFILE; 

slog("Received bytes totally: $total_recv");
pstatus($filename, $total_recv, "Analysis in progress. Please wait.");

if ( ! -f $file ) {
    slog("Exiting. File '$file' does not exist.");
    pstatus($filename,0,"An error occurred. Exiting");
    die "Exiting. File '$file' does not exist.";
} else {
    slog("File uploaded: $file.");
}

($dev,$ino,$mode,$nlink,$uid,$gid,$rdev,$size,$atime,$mtime,$ctime,$blksize,$blocks) = stat "$file";

$run = $ANALYSIS . " $ssparam $file " . '-o -';

slog("Command to run: " . $run);

#$result = system($run);
$result = qx/$run/;

# Write progress to status file, for reading from 'progressbar.cgi'
$filename =~ s/\.gz//g;  # Remove '.gz' from filename because IE cant handle it
pstatus($filename, $total_recv, "Analysis completed.");

slog("Results returned with error " . ($? >> 8));
# Print result to STDOUT (browser) 
#print $result;

print $query->start_html('Results');
print $query->h1('Completed analysis');

#print "Results are returned<br>\n";

print $query->end_html();

# Also print to a file for later retrieval.
$outfile = "/var/wwwtornado/htdocs/slac/results/$uploadid.$filename.txt";
open OUTFILE,">$outfile";
print OUTFILE $result;
close OUTFILE;



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
    openlog('upload2.cgi', 'cons,pid', 'local2');
    syslog('info', '%s', @_);
    closelog;
}

sub pstatus {
    # Print progress to status file, for reading from 'progressbar.cgi'
    $filename = @_[0];
    $total_recv = @_[1];
    $status = @_[2];
    
    open STATUS, ">$statfile";
    flock(STATUS,LOCK_EX);
    print STATUS "$filename\n";
    print STATUS "$total_recv\n";
    print STATUS "$status\n";
    flock(STATUS,LOCK_UN);
    close STATUS;
}


sub sanitize {  # Sub to sanitize filenames and check for illegal characters
    my $x = shift;
    slog("Sanitizing $x");
    print STDERR "$x\n";
    my $count = 0;
    if (($x =~ s/[`&'*?^()#$|\>\<\[\]\n\r]//g) gt 0) {
        #print STDERR "Error: $x\n";
        return 99;

    } else
    {
        return 0;
    }
}
