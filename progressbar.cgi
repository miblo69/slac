#!/usr/bin/perl
# $Id: progressbar.cgi,v 1.2 2004/08/27 08:35:08 mibl Exp mibl $

# This is to show the progress on file uploads

use CGI;

$query = new CGI;
$refreshtime = 2;  # Interval between meta-refresh of progress page

use Sys::Syslog;                          # all except setlogsock, or:
use Sys::Syslog qw(:DEFAULT setlogsock);  # default set, plus setlogsock

slog("Starting progressbar.cgi");

slog("Remote host: " . $query->remote_host());
slog("Request method: " . $query->request_method());
slog("HTTP Headers: " . $query->http());

foreach $x ($query->http()) {
    slog($x . ': ' . $query->http($x));
}


slog("Retrieved POST value-pairs:");
%P = $query->Vars;
#slog("%P");
foreach $p1 (keys %P) {
    slog("  $p1\: $P{$p1}");
}

$progressid = $query->param("ProgressID");
if (sanitize($progressid) ne 0) {
    slog("Invalid characters found in UploadID: $uploadid. Exiting.");
    die "Manipulation of ProgressID detected. Aborted.";
}


# Get status from progressfile
$statfile = "/var/tmp/$progressid.log";
$link = '';
if (-f $statfile) {
    open STATUS, "<$statfile";
    @res = <STATUS>;
    #$filename = readline STATUS;
    $filename = @res[0];
    #$bytesrcvd = readline STATUS;
    $bytesrcvd = @res[1];
    $status = @res[2];
    close STATUS;

    if ($status =~ m/Analysis completed/i) {  
	slog("Status received: $status, not refreshing any more.");
	print $query->header;
	$link = "The results\: <a href='http://www.tornado.se/slac/results/$progressid.$filename.txt' target='_new'>$progressid.$filename.txt</a>\n"; 
	$link .= "<br>Analysis file we be available for download for 24 hours<br>\n";
    } else {
	print $query->header(-type=>'text/html',
			     -Refresh=>$refreshtime . ';http://www.tornado.se/cgi-bin/progressbar.cgi?ProgressID=' . $progressid);;
    }
    print $query->start_html(-title=>'Progress ' . $progressid,
			     -style=>{'src'=>'/images/tornado.css'});

    print "File ID: " . $query->param('ProgressID');
    print '<br>';
    print "Filename: $filename<br>\n";
    print "Bytes uploaded: $bytesrcvd<br>\n"; 
    print "Status: $status<br>\n";
    print localtime() . "<br>\n";
    print $link;
    print $query->end_html;


} else {
    slog("File $statfile not found. Assumed upload in progress.");
    print $query->header(-type=>'text/html',
			 -Refresh=>$refreshtime . ';http://www.tornado.se/cgi-bin/progressbar.cgi?ProgressID=' . $progressid,
			 -style=>{'src'=>'/images/tornado.css'});
    print $query->start_html(-title=>'Progress indicator' . $progressid,
			     -style=>{'src'=>'/images/tornado.css'});
    print "Progress ID: " . $query->param('ProgressID');
    print "<br>File uploading.<br>";
    print localtime() . "<br>\n";
    print $query->end_html;

}


sub slog {
    setlogsock('unix');
    openlog('progressbar.cgi', 'cons,pid', 'local2');
    syslog('info', '%s', @_);
    closelog;
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
