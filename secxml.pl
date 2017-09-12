#!/usr/bin/perl
# $Header: /usr/local/secsrch/RCS/secsrch.pl,v 1.50 2003/04/27 20:12:22 mibl Exp $
# $Revision: 1.50 $
# (C) Mike Blomgren 2001-02-21
# mibl@a51.mine.nu
# 
# Perl script to parse Webserver logfiles, and search for
# any security anomalies, and report them accordingly, thus SecSrch.
# The script is intended to be used offline, i.e. to sift through
# 'yesterdays' access.log in a cron job, or at will.
#
# Handles 'Common Log Format' (e.g. Weblogic), Standard IIS (IN??????.LOG),
# IIS Extended logfiles etc.
# It should be fairly simple to add other logformats (if you know Perl...)
# 
# This script comes with the standard disclaimers. I.e.
# there are no warranties or guaranties whatsoever.
# Use at your own risk, and if it causes problems - your loss.
# 
# 2000-12-15 Start: First attempt att writing a logfile parser...
# 2001-01-29 Added: Support for mulitiple .gz files with wildcards ex: secsrch.pl apwww1*.gz
# 2001-01-30 Added: Counter for # of unique IP's
# 2001-01-30 Added: Counter for # of status codes
# 2001-02-08 Cleaned: Cleaned out comments, and unnecessary 'testing' code.
# 2001-02-19 Released: 2.13 Initial public release.
# 2001-02-25 Added: Count of HTTP versions. Stripped " from URL.
# 2001-02-28 Added: Optional FQDN name resolution.
# 2001-03-02 Changed: Reports now contain headers, thus shorter lines
# 2001-04-16 2.20 Added: Hits/Hour - for a general 'feel' of the visitors hours.
# 2001-04-16 2.21 Added: Top HIT'ers.
# 2001-04-26 2.22 Added: Percent of total, to TOP HIT'ers
# 2001-05-10 2.23 Added: -N switch to not perform name resolution
# 2001-06-14 2.24 Bug: Handling of 'Succesful Downloads' had logic error.
# 2001-08-20 2.25 Added: $CRLF variable to accomodate for unix & DOS output format
# 2001-09-03 2.26 Added: Rank on 'Top HIT'ers' list
# 2002-05-22 2.27 Started rework for 'logger' funktion
# 2002-06-10 2.28 Added syslog logging of progress
#                 Added Cookie hijacking detection
# 2002-06-16 2.29 Added detection of URI Query manipulation attempts
# 2002-08-03 2.30 Various improvements
# 2003-03-18 2.31 Started working on long-time statistics gathering
# 2003-03-22 2.32 Also added XML output...
#
# To Do...:
# Add 'Bursty surfing detection' 
# Add 'Crawler detection'
# Improve parsing performance. 2000-4000 lines/second is not impressive...
#   and the parsing is what sucks all performance.
# Add XML modularized output for easy ASCII/HTML/whatever output
# Add Analysis based on time - WHEN do 5xx errors occur, etc? Related to a single time, or spread out during the day
# Add maximum hits per a single second (to locate possile resource starvation attempts)
# Look for any delays in traffic (log times without any hits) - To locate succesful DoS
# Do Whois-lookup on IP-addresses in printed in report.
# Add Automatic detection and split of logfiles which contain data from several webservers
#

$VERSION = '2.33';

$res = 'true';  # Set to true if we should attempt to resolve IP's to FQDN
#$res = 'false';
 

#$y = "kelle/hej.asp?du=jag&hen=nu&bu=na";
#print urlencode($y) . "\n";
#open OUT, ">&STDOUT";
#prntx ('kalle','kula','ruta');

#exit;

# Select Output-format (DOS or Unix - CRLF or CR)
#$CRLF = "\r\n";  # 0x0D 0x0A  (DOS-format)
$CRLF = "\n";  # 0x0A (Unix -format)
$iisext = 0;   #Boolean value for handling IIS Extended Logs.

# Required to handle compressed files. Remove if not needed...
use Compress::Zlib;
use Getopt::Std;
use Socket;   ## For dns resolver
use Archive::Zip qw ( :CONSTANTS );
#use Archive::Zip::Member;
use Benchmark;
use Time::HiRes;
$timing = 0;  # Used for debug purposes to find time-consuming operations

use URI::Escape;

use Sys::Syslog;                          # all except setlogsock, or:
use Sys::Syslog qw(:DEFAULT setlogsock);  # default set, plus setlogsock

# For graphing functions. Comment out if not needed
#use GD::Graph::bars;
#use GD::Graph::hbars;
#use GD::Graph::Data;

slog('Starting Exec');

getopts('hvNsXo');  # If set, then don't do a name lookup
# h - only print help
# v - print version and exit
# N - don't do name lookups
# s - Only print stats
# X - Use XML output for report
# o - Overwrite output file if it exists

#getopts('v');
 
# Check which environment we're running in
if ($ENV{'OS'} =~ m/windows/i) {
    $os = 'win'; 		#Windows
    $osenv = 'OS';
}
elsif ($ENV{'OSTYPE'} =~ m/solaris/i) {
    $os = 'sol';		#Solaris
    $osenv = 'OSTYPE';
}
else {  
    $os = 'unknown';
}

#print "Assumed $os. Running under $ENV{"$osenv"}\n" ;


# Hash with Months - This is to map names to numbers.
# Needs to be altered if non-english... 
# (A 'use locale' procedure might work, but I haven't tried....)
%MONS = ( 'Jan' => '01', 'Feb' => '02', 'Mar' => '03', 
	  'Apr' => '04', 'May' => '05', 'Jun' => '06',
	  'Jul' => '07', 'Aug' => '08', 'Sep' => '09', 
	  'Oct' => '10', 'Nov' => '11', 'Dec' => '12');

# Hash with HTTP status Codes. Mostly for reference. Only the first word in 
# capital letters is actually printed in the results...
%STATCODE = ( '100' => 'CONTINUE', 
	      '101' => 'SWITCH_PROTOCOLS', 
	      '200' => 'OK', 
	      '201' => 'CREATED', 
	      '202' => 'ACCEPTED', 
	      '203' => 'PARTIAL', 
	      '204' => 'NO_CONTENT', 
	      '205' => 'RESET_CONTENT', 
	      '206' => 'PARTIAL_CONTENT', 
	      '300' => 'AMBIGUOUS', 
	      '301' => 'MOVED', 
	      '302' => 'REDIRECT', 
	      '303' => 'REDIRECT_METHOD', 
	      '304' => 'NOT_MODIFIED', 
	      '305' => 'USE_PROXY',
	      '307' => 'REDIRECT_KEEP_VERB', 
	      '400' => 'BAD_REQUEST', 
	      '401' => 'DENIED', 
	      '402' => 'PAYMENT_REQ', 
	      '403' => 'FORBIDDEN', 
	      '404' => 'NOT_FOUND', 
	      '405' => 'BAD_METHOD', 
	      '406' => 'NONE_ACCEPTABLE', 
	      '407' => 'PROXY_AUTH_REQ', 
	      '408' => 'REQUEST_TIMEOUT',
	      '409' => 'CONFLICT', 
	      '410' => 'GONE', 
	      '411' => 'LENGTH_REQUIRED', 
	      '412' => 'PRECOND_FAILED',
	      '413' => 'REQUEST_TOO_LARGE', 
	      '414' => 'URI_TOO_LONG', 
	      '415' => 'UNSUPPORTED_MEDIA', 
	      '416' => 'NOT SATISFIABLE',
	      '417' => 'EXPECTATION FAILED',
	      '449' => 'RETRY_WITH', 
	      '500' => 'SERVER_ERROR', 
	      '501' => 'NOT_SUPPORTED', 
	      '502' => 'BAD_GATEWAY',
	      '503' => 'SERVICE_UNAVAILABLE', 
	      '504' => 'GATEWAY_TIMEOUT', 
	      '505' => 'VERSION_NOT_SUPPORTED');

$mindate = '';
$maxdate = '';

$starttime = time;
$starttimetext = localtime;

$infile = $ARGV[0];
$outfile = $ARGV[1];
$statsfile = '/tmp/stats.log';
$statsfile = '&STDOUT';
slog('Infile: ' . $infile);

$topmax = 20;		# How many 'TOP HIT'ers' to display

# Check if we want help....
if ($opt_h eq 1) {
    print "SecSrch version $VERSION$CRLF";
    print "Useage: [cat\|type] \<infile\> \| [perl] secsrch.pl \- [outfile]\n";
    print "or      [perl] secsrch.pl [\-Nvhs] <infile> [outfile]$CRLF";
    print "or      [perl] secsrch.pl [\-Nvhs] \'<infile\*.gz>\' [outfile]$CRLF$CRLF";
    print "or      [perl] secsrch.pl [\-Nvhs] \'<infile\*.gz>\' [outdir]$CRLF$CRLF";
    print "If \-N is used, Name resolution will not be performed. $CRLF";
    print "If \'\-\' is used for <infile>, STDIN will be used for input.$CRLF";
    print "If \'\-\' is used for <outfile>, STDOUT will be used for output.$CRLF$CRLF";
    exit;
}

#Check for version info
if ($opt_v eq 1) {	
    print "$CRLFSecSrch by Mike Blomgren, v$VERSION$CRLF";	
    exit; 
}



# Which files do we open?....
if ($infile eq '-') {
    @list = '-';
    if (($outfile eq '') || ($outfile eq '-'))
    {	
	$outfile = '&STDOUT';	
    }
    # Else outfile = outfile...
} else {
    @list = glob $infile;   # Did we specify wildcard
    
    if (join( '', @list) eq "") {
	slog("No Files found matching $infile.$CRLF");
	die "No Files found matching $infile.$CRLF";
    }
    $list[0] =~ m/[\/\\]*?([\d\.\w\-\_]+)$/;
    # If '-' specified as outfile, then open STDOUT
    if ($outfile eq '-') {
	$outfile = '&STDOUT';
    }
    elsif ($list[1] ne '')
    {	# If more than one file is being analyzed - use a different output filename,
	# to indicate that multiple files have been analyzed into one result file.		
	if ( -d $outfile) {
	    $outfile = $outfile . '/SecSrch.Multi.' . $1 . '.log';
	} else {
	    if ($outfile eq '') {	
		$outfile = 'SecSrch.Multi.' . $1 . '.log';
	    }
	}	
    }
    else
    {	# If only one infile, use 'standard' output filename.
	if ($outfile eq '')
	{
	    $outfile = 'SecSrch.' . $1 . '.log';
	}
	if ( -d $outfile ) 
	{
	    $outfile = $outfile . '/SecSrch.' . $1 . '.log';	
	}
	# Else $outfile = $outfile...
    }
    
}

if ((-f $outfile) && !($opt_o))
{
    print "File \'$outfile\' already exists. Exiting.$CRLF$CRLF";
    exit ;
}

open (OUT , ">$outfile") || die "Can't open $outfile for output\.";
open (STATS, ">$statsfile") || die "Can't open $statsfile for output\.";
#print "Infile(s): " . join (" $CRLF",@list) . " $CRLFOutfile: $outfile $CRLF";
	
foreach $file (@list)
{ 
    slog("Starting with: $file");
    if ($file =~ m/\.gz$/)
    {
	slog('Compressed .gz file detected');
	$gz = gzopen($file, "rb") or die "Cannot open $file: $gzerrno$CRLF" ;
	while ($gz->gzreadline($buffer) > 0)
	{
	    $_ = $buffer;
	    # Can we parse the current line? 
	    if (splitline() != -1)
	    {
		# Yepp, then make statistics...
		makestats();
	    }
	}
	die "Error reading from $file: $gzerrno$CRLF" if $gzerrno != Z_STREAM_END ;
	$gz->gzclose() ;
    } 
    #elsif ($file =~ m/\.zip$/) {
    #slog("Zip File");
    #$zip = Archive::Zip->new();
    #die 'read error' unless $zip->read($file) == AZ_OK;
    #my @member = $zip->memberNames();
    #print $zip->numberOfMembers();
    ##print $zip->memberNames;
    #foreach $x (@member) {
    #    print "$x\n";
    #    $zip->extractMember($x, '/tmp/' . $x);
    
    # Open and start reading extracted file
    #    open (IN, "</tmp/$x") || die "Can't open $file for input.$CRLF";
    #    while (<IN>)
    #    {
    #	# Can we parse the current line?
    #	if (splitline() != -1) {
    #	    if (($date le $mindate) || ($mindate eq '')) {$mindate = $date};
    #	    if (($date gt $maxdate) || ($maxdate eq '')) {$maxdate = $date};
    #	    # Yepp, then make statistics...
    #	    makestats();
    #	}
    #    }
    #    close IN;
    #} 
    #}
    else {
	if ($file eq '-') {$infile = '&STDIN'};
	open (IN, "<$file") || die "Can't open $file for input.$CRLF"; 
	#Start reading file
	while (<IN>) 
	{		
	    # Can we parse the current line? 
	    if (splitline() != -1) {
		#if (m/getting/) {print "problems: $_"; exit;}
		if (($date le $mindate) || ($mindate eq '')) {$mindate = $date};
		if (($date gt $maxdate) || ($maxdate eq '')) {$maxdate = $date};
		# Yepp, then make statistics...
		makestats();
		#print "returned\n";
	    }
	}	
	close IN;
    }	
}

if ($opt_s) {
    printstats();
} else {
    if ($opt_X) {
	printxml();
    } else {
	printall();
    }
}

slog('Exiting...');
exit 0;


sub splitline {
    $numlines++;
    #print "$timing\n";
    if ($timing == 1) {
	my $t0 = new Benchmark;
	print "$t0\n";
    }
	
    # Split Logfile line into values.
    
    # Check for lines with comments
    if (m/^\s*?\#/) {
	#$badlines++;
	#$logformat{'Ignored'}++;
	if (m/^\s*\#Fields\:\s(.*)/) {
	    $logformat{'Field definitions'}++;
            @header = split(/\s/, $1);
            #print join("\n",@header);
            $iisext = 1;   # If we see a #Field line, we assume the whole file
	                   # is IIS Extended format. And set that assumption here.
        }
	else
	{
	    $logformat{'Ignored Comments'}++;
	}
	if (m/^\#Date\: (\d\d\d\d\-\d\d\-\d\d)\s(\d\d\:\d\d:\d\d)/) {
	    $exdate = $1;
	    #print "Assuming IIS EX file: $1 - $2$CRLF";
	}
	return -1;
    }

    if ($iisext eq 1) {
	#if (m/getting/) {print; print "problems"; exit;}
	$logformat{'MS-IIS Extended'}++;
	# Check for the pesky NULL lines in IIS log files
	if ((tr/\x00//)) { return -1};
	undef %HASH;
	@fields = split /\s/;
	#print join("\n",@fields);
	#if (m/getting/) {
	#    print; 
	#    print "problems"; 
	#    print join("\n",@fields);
	#    exit;
	#}
	$c = 0;
	foreach $x (@header) {
	    #print "$x $fields[$c]\n";
	    @HASH{$x} = $fields[$c];
	    $c++;
	}
	$ip = $HASH{'c-ip'};
	# Sanity Check
	if (not $ip =~ m/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/) {
	    #print "no match\n";
	    return -1;
	}
	$url = $HASH{'cs-method'} . ' ' . $HASH{'cs-uri-stem'};
	$method = $HASH{'cs-method'};
	#if ($method eq '-') {print "Illegal: $_\n"}
	$query = $HASH{'cs-uri-query'};
	#print "IIS Q: $query\n";
	$user = $HASH{'cs-username'};
	$sitename = $HASH{'s-sitename'};
	$serverip = $HASH{'s-ip'};
	if ( (not $serverip =~ m/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/)) {
            #print "no match\n";
            return -1;
        }
 
	$cname = $HASH{'s-computername'};
	$date = $HASH{'date'} . ' ' . $HASH{'time'};
	#if ($date =~ m/get/) {
	#    print;
	#}
	$httpver = $HASH{'cs-version'};
	$status = $HASH{'sc-status'};
	$referer = $HASH{'cs(Referer)'};
	$cookie = $HASH{'cs(Cookie)'};
	$browser = $HASH{'cs(User-Agent)'};
	$len = $HASH{'sc-bytes'} + $HASH{'cs-bytes'};

	# Modi by MB 030416:
	#$date =~ m/(\d\d\d\d)\-(\d\d)\-(\d\d)\s(\d\d)\:(\d\d)\:(\d\d)/;
	#$day = $3; $mon = $2; $yr = $1; $hr = $4; $mi = $5; $se = $6;
	if ($date =~ m/(\d\d\d\d)\-(\d\d)\-(\d\d)\s(\d\d)\:(\d\d)\:(\d\d)/) {
	    $day = $3; $mon = $2; $yr = $1; $hr = $4; $mi = $5; $se = $6;
	}

	#print "$HASH{'time'}\n";
	$uri = $url . '?' . $query;
	#if ($timing == 1) {
	#    my $t1 = new Benchmark;
	#    print "Splitline: ".timestr(timediff($t1,$t0));
	#}
	return;
    } 
    else {
	
    # Common Log Format (Weblogic, Apache etc)
	if ( m/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})   # IP Address
	     
	     \s(.+?)                        # User
	     \s(.+?)                        # unused
	     \s(\[.+\])                     # Date
	     \s\"(.*)\s               # Url
	     
	     (?:(\?.*\s))?
	     (?:(.*?)\")? 		  # Match regardless of HTTP Version.
	     \s(\d+?)                       # Statuscodes
	     \s([\-\d]+?)                   # Size
	     \s(?:\"(.*?)\")?                    # Optional Referer
	     (?:\s\"(.*?)\")?                    # Optinal Browser type
	     (?:\s\"(.*?)\")?               # Optional Cookie
	     /iox )                    
	{
	    
	    $logformat{'Common Log Format'}++;
	    $ip = $1; $na1 = $2; $user=$3; $date = $4;
	    $url = $5; 
	    
	    #print "DBG: $url\n";
	    $query = $6;
	    $httpver = $7; $status = $8; $len = $9;
	    $referer = $10; $browser = $11; $cookie = $12;
	    $uri = $url . '?' . $query;
	    #print "$httpver\n";
	    if ($url =~ m/([\w]+)\s.*/) {
		$method = $1;
		#print "M: $method\nU:$url\n";
	    }
	    if ( $date =~ m/^\[(\d{1,2})
		 \/(.{3})
		 \/(\d\d\d\d)
		 \:(\d+?)
		 \:(\d+?)
		 \:(\d+?)
		 \x20(.+?)\]/ox)
	    {
		$day = $1; $mon = $2; $yr = $3; $hr = $4; $mi = $5; $se = $6;
		$date = "$yr\-$MONS{$mon}\-$day $hr:$mi:$se";
		$epochtime = "";
	    }
	    return 1;
	}
	
	#IIS Logs Standard Logs (INxxxxxx.log)
	elsif (m/^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})
	       \,\s*(.+?)
	       \,\s(\d{2,4}).(\d{1,2}).(\d{1,2})
	       \,\s(\d+):(\d\d:\d\d)
	       \,\s([\w\d]+?)
	       \,\s(\w+?)
	       \,\s(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})
	       \,\s(\d+?)
	       \,\s(\d+?)
	       \,\s(\d+?)
	       \,\s(\d+?)
	       \,\s(\d+?)
	       #\,\s(\w+?)
	       \,\s(.+?) 
	       \,\s(.+?)
	       \,.*/ox)
	{
	    $logformat{'IIS Standard'}++;
	    $hr = sprintf("%02d", $6);
	    $ip = $1; $user=$2; $date = "$3-$4-$5 $hr:$7" ;
	    #print "D $date\n";
	    $url = $16 . ' ' . $17; $status = $14; $len = $10;
	    $method = $16;
	    undef $httpver;
	    return 1;

	} 
	
	# No Match...
	else 
	{
	    #print;
	    $logformat{'Unknown'}++;
	    #$badlines++;
	}
    }
    #if ($timing == 1) {
#	my $t1 = new Benchmark;
#	print "Splitline: ".timestr(timediff($t1,$t0));
#	
#    }
	    
}

sub makestats {
    #print "making $url\n";
    # Start collecting stats on the parsed logfile entries
    #$numlines++;

    # Check for Exceedingly Long URL's before doing more statistics
    if ((length $url) > 250 ) {
	$lenu = length($url);
        $url = substr($url, 0, 15) . ' [ Truncated ] ' . substr($url, length($url)-15,15);
        $s18{"$url¤$ip¤$lenu¤$status"}++;
    }
    
    
    # Look for 'File not found' or 'Forbidden' messages, but filter 
    # out the obvious 404 generators...
    if (($status =~ m/404|403|406/))
	#&& (not $url =~ m/favicon|GET.\/images|\/img\/meny/ix))
    {
	$s0{"$ip¤$url"}++;
	$s01{"$status¤$url"}++;
	$s02{"$ip"}++;
	# Why do we resolve the ip-address here??? /Mike
	if ($sip{$ip} eq undef) {	$sip{$ip} = resolve($ip) };
    }
    
    # Logged In Users
    if (($user ne '-') and ($user ne 'N/A')) 
    {
	$s1{"$user¤$ip"}++;
	# Why do we resolve the ip-address here??? /Mike
	if ($sip{$ip} eq undef) {	$sip{$ip} = resolve($ip) };
	#print "$_\n";
    }

    $s10{"$user"}++;
    
    # Unauthorized messages
    if ($status eq '401')
    {
	$s2{"$status¤$ip¤$url¤$user"}++;
    }
    
    # Look for 'dangerous' files successfully downloaded to the client
    # This needs to be modified depending on what system you'r running (unix/VMS/Windows/whatever)
    if ($status eq '200') {
	if ($url =~ m/passwd|\/etc\/shadow|nc.exe|cmd1\.exe|ncx\.exe|inetd|\/services|access\.log|cmd\.exe|\.\%..\%..|\.url|\.bat/ix) {
	
	    $s3{"$ip¤$url"}++;
	}
    }
    
    # Show URL's which have generated a 5xx error
    if ($status =~ m/^5/)
    {
	$s4{"$status¤$url"}++;
	$s41{"$status¤$url¤$ip"}++;
	$s42{"$status¤$ip"}++;
	if ($sip{$ip} eq undef) { $sip{$ip} = resolve($ip) };
	$s43{"$date¤$ip"}++;
	print "$date $ip\n";
    }
    
    #Count number of unique IP's, and HITS per IP
    if ($iptab{$ip} eq undef)
    { 
	$numip++;
    }

    # Count hits per IP
    $iptab{$ip}++;
    
    # Count number of statuscodes
    $s5{"$status"}++; 
    
    # Count number of HTTP Versions
    if (defined $httpver) {
	$s6{$httpver}++;
	#print "H:$httpver  Q:$query\n";
    }
    
    # List requests with illegal or missing http version fields. 
    #if ((not $httpver =~ m/^HTTP\/\d\.\d$|N\/A/i) && (defined $httpver))
    if ((not $httpver =~ m/^HTTP\/1.0$|^HTTP\/1.1$|N\/A/i) && (defined $httpver))
    {
	$s61{"$httpver¤$url¤$ip"}++;
    }
    
    # Get Hits per hour
    $s7{$hr}++;
    if ($s7{$hr} > $hrmax) {$hrmax = $s7{$hr}}

    # Look at Referers
    
    unless ($referer =~ m/^\s*$/) { $s11{$referer}++;}

    # Count Browser versions
    unless ($browser =~ m/^\s*$/) {$s12{$browser}++;}

    # Check for Cookie Manipulation  - i.e. same cookie from different IP's
    if (($cookie ne '-') && ($cookie ne '')) {
	#print "Cookie: $cookie   - IP: $ip\n";
	if (defined $s13{$cookie}) {
	    if (($s13{$cookie} ne $ip) && (! defined $s14{"$cookie¤$ip"})){
		#print "Cookie: $cookie \n Old IP: $s13{$cookie} New IP: $ip\n";
		#Then we have problems...
		
		#$s14{"$cookie"}++;
		$s14{"$cookie¤$ip"}++;
		$s14{"$cookie¤$s13{$cookie}"}++;
	    } 
	    	    
	} else {
	#    #print "CIP: $ip\n";
	    $s13{$cookie} = $ip;
	    #$s14{"$cookie¤$ip"}++;
	    #$s14{"$cookie¤$ip"}++;
	    #print "CIP: $cookie = $ip\n";    
	    #}
	}
    }
    
    # Check for unsuccessfull attempts to List directories
    #print "$url\n";
    if (($url =~ m/\/$/) && ($status ne '200') && ($status ne '304') && ($status ne '302')) {
	#print "URL $url $status\n";
	$s15{"$ip¤$url¤$status"}++;
	$s151{"$ip"}++;
    }
    
    # Check for attempts to manipulate form data. 
    # For example 'SELECT' in the Query, or other 'abnormal' characters
    if ($query =~ m/select|\'|\"|\;|javascript|\>|\</gi) {
	$s16{"$ip¤$query"}++;
    }

    # Check for Anonymous Proxy Scanning, i.e. URL starts with 'HTTP...' or  
    # uses CONNECT method
    if (($url =~ m/^[\w]+?\s+HTTP[s]*\:/i) || ($url =~ m/^connect/i)) {
	#print $url;
	$s17{"$ip¤$status¤$url"}++;
    }

    # List HTTP Methods found
    if ($method ne '') {
	$s19{$method}++;
    }

    # Check if Several Servers listed
    $s20{$serverip}++;

    

    #print "stats done\n";
}

sub printxml {
    print OUT '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>' . "\n";
    # Check if results are OK, before mailing report
    if ($numlines eq $logformat{'Unknown'}) {
	exit 99;
    }
    slog('Printing XML output');
    print OUT "<report version=\"$VERSION\" logdatestart=\"$mindate\" logdateend=\"$maxdate\">\n";
    
    print OUT "<reporttitle>Security Log File Analysis</reporttitle>\n";

    print OUT "<inputfiles>" . join (" ",@list) . "</inputfiles>\n";
    print OUT "<outputfiles>$outfile</outputfiles>\n";
    #print OUT "<stats execstart=\"$starttimetext\" execstop=\"" . localtime();
    prntx ("execstart", $starttimetext);
    prntx ("execstop", localtime(). "");
    prntx ('rowsanalysed',$numlines);
    prntx ('nripaddr',$numip);
    prntx ('perf',  $numlines / (time - $starttime + 1));
    prntx ('nameresoff', $opt_N);
       
    #print OUT "\" rowsanalysed=\"$numlines\" nripaddr=\"$numip\" perf=\"";
    #print OUT $numlines / (time - $starttime + 1) . "\" ";
    #print OUT "nameresoff=\"$opt_N\">\n";
    #print OUT "Outputfile: $outfile $CRLF";
    #print OUT "<executionstart>" . $starttimetext . "</executionstart>\n";
    #print OUT "<executionstop>" . localtime() . "<executionstop>\n";
    #printf OUT "<analyzedrows>%d</analyzedrows>\n", $numlines;
    #printf OUT "nr of non-analyzed rows:    %7d $CRLF", $logformat{'UNKNOWN'};
    #printf OUT "<nrofipaddresses>%d</nrofipaddresses>\n", $numip;
    #printf OUT "<performance>" . $numlines / (time - $starttime + 1) . "</performance>\n";
    #print OUT "</stats>\n";
    print OUT "<logformats>\n";
    prntx('title','Logformats');

    foreach $x (keys %logformat) {
	print OUT "  <rec>\n";
	#printf OUT "  <logformat format=\"%s\" nrfound=\"%d\" />\n", $x, $logformat{$x};
	#print OUT "<logformat>\n";
	prntx ("format", $x);
	prntx ("nrfound", $logformat{$x});
	#print OUT "</logformat>\n";
	print OUT "  </rec>\n";
    }

    print OUT "</logformats>\n\n";

    slog("Nr of Analyzed rows: $numlines");
    slog("Rows/sec: " . $numlines / (time - $starttime + 1));
    #printf OUT "nr of analyzed rows/second: %7d $CRLF", $numlines / (time - $starttime + 1);
    #printf OUT "nr of $logformat{'CLF'}\n";
    
    #if ($opt_N ne '') 
    #{  print OUT "<nameresolution>Off</nameresolution>\n"; }
    #else
    #{  print OUT "<nameresolution>On</nameresolution>\n"; }
    
    # Show number of hits/hour
    print OUT "<hitsperhour>\n";
    prntx('title','Hits per hour');
    sumhash (\%s7);
    #print OUT "Totally $sum and $uniq unique.$CRLF";
    #printf OUT "%7s  %9s$CRLF",  'Hour', 'Hits';
    #foreach $k (sort keys %s7)
    #print "<rec>\n";
    for ($k=0;$k<24;$k++)
    {
	@_ = split "¤", $k;
	$hits = $s7{sprintf("%02d", $k)};
	if ($hits eq '') { $hits = '0'};
	#printf (OUT "  <hits hour=\"%d\">%s</hits>\n",  $_[0], $hits);
	print OUT "  <rec>\n";
	prntx('hour',$_[0]);
	prntx('hits',$hits);
	print OUT "  </rec>\n";
    }
        
    print OUT "</hitsperhour>\n\n";



    # Dangerous files...
    #print OUT "$CRLF********** Successful attempts to retrieve \'Dangerous\' files ********** $CRLF";
    sumhash (\%s3);
    print OUT "<dangerousfiles total=\"$sum\" uniq=\"$uniq\">\n";

    prntx('title','Successful attempts to retrieve Dangerous files');
    #print OUT "This could inidicate a serious security breach.$CRLF";
    #print OUT "Totally $sum and $uniq unique.$CRLF";
    #printf OUT "%7s  %-15s  %-50s$CRLF",  'Count', 'Src IP', 'URL' ;
    foreach $k (sort {$s3{$b} <=> $s3{$a}} keys %s3 )
    {
	@_ = split "¤", $k;
	print OUT "<rec>\n";
	prntx('count',$s3{$k});
	prntx('srcip',$_[0]);
	prntx('url',$_[1]);
	print OUT "</rec>\n";
	#print OUT "<dangerousfile count=\"$s3{$k}\" srcip=\"$_[0]\" url=\"$_[1]\"/>\n";
	
	#printf (OUT "%7d  %-15s  %-50s$CRLF",  $s3{$k}, $_[0], $_[1]);
    }
    print OUT "</dangerousfiles>\n\n";
    
    # Unauthorized
    #print OUT "$CRLF********** Users who have accessed protected pages ********** $CRLF";
    sumhash (\%s2);
    print OUT "<unauthorized total=\"$sum\" uniq=\"$uniq\">\n";
    prntx('title', 'Users who have accessed protected page');
    foreach $k (sort {$s2{$b} <=> $s2{$a}} keys %s2 )
    {
	@_ = split "¤", $k;
	#print OUT "<entry>\n";
	print OUT "  <rec>\n";
	prntx('count',$s2{$k});
	prntx('status',$_[0]);
	prntx('srcip',$_[1]);
	prntx('user',$_[3]);
	prntx('url',$_[2]);
	print OUT "  </rec>\n";
	#printf OUT " <unauthorized_user count=\"%s\" status=\"%s\" srcip=\"%s\" user=\"%s\" url=\"%s\"/>\n", $s2{$k},$_[0], $_[1], $_[3], $_[2];
	#print OUT "</entry>\n";
    }
    
    print OUT "</unauthorized>\n\n";


    #print OUT "$CRLF********** Logged in Users **********$CRLF";
    sumhash (\%s10);
    
    print OUT "<logged_in_users total=\"$sum\" uniq=\"$uniq\">\n";
    prntx('title','Logged in users');
    #print OUT "Totally $sum and $uniq unique.$CRLF";
    #printf(OUT "%9s  %-15s$CRLF",  'Count', 'User');
    foreach $k (sort {$s10{$b} <=> $s10{$a}} keys %s10 )
    {
	@_ = split "¤", $k;
	print OUT "  <rec>\n";
	prntx('user',$_[0]);
	prntx('count', $s10{$k});
	print OUT "  </rec>\n";
	#printf(OUT " <loggedinuser count=\"%d\" user=\"%s\"/>\n",  $s10{$k}, $_[0]);	
    }
    print OUT "</logged_in_users>\n\n";

    
    # Logged in users per IP-address (excl Anonymous) 
    sumhash (\%s1);
    print OUT "<logged_in_users_per_ip total=\"$sum\" uniq=\"$uniq\">\n";
    prntx('title', 'Logged in user per IP-address');
    foreach $k (sort {$s1{$b} <=> $s1{$a}} keys %s1 )
    {
	@_ = split "¤", $k;
	print OUT "  <rec>\n";
	prntx('count',$s1{$k});
	prntx('user',$_[0]);
	prntx('srcip',$_[1]);
	prntx('fqdn',$sip{$_[1]});
	print OUT "  </rec>\n";	
	#printf OUT " <userperip count=\"%d\" user=\"%s\" srcip=\"%s\" fqdn=\"%s\"/>\n",  $s1{$k},$_[0], $_[1], $sip{$_[1]};
    }
    print OUT "</logged_in_users_per_ip>\n\n";
        

    # Count of all Statuscodes...
    sumhash (\%s5);
    print OUT "<statuscodes total=\"$sum\" uniq=\"$uniq\">\n";
    prntx('title','Statuscodes');
    foreach $k (sort keys %s5 )
    {
        @_ = split "¤", $k;
        print OUT "  <rec>\n";
        prntx('count',$s5{$k});
        prntx('status',$_[0]);
        prntx('statusname',$STATCODE{$_[0]});
        print OUT "  </rec>\n";
	
        #printf(OUT "<codes count=\"%d\" status=\"%s\" statusname=\"%s\"/>\n" ,$s5{$k}, $_[0], $STATCODE{$_[0]});
	
        #print OUT "</entry>\n";
    }
    print OUT "</statuscodes>\n\n";


    # Count of all HTTP Methods...
    sumhash (\%s19);
    print OUT "<httpmethods total=\"$sum\" uniq=\"$uniq\">\n";
    prntx('title', 'List of HTTP methods found');
    foreach $k (sort {$s19{$b} <=> $s19{$a}} keys %s19 )
    {
	@_ = split "¤", $k;
	print OUT "  <rec>\n";
	prntx('count',$s19{$k});
	prntx('method',$k);
	print OUT "  </rec>\n";
	printf(OUT "  <method count=\"%d\" methodstr=\"%s\"/>\n",  $s19{$k}, $k,);
    }
    print OUT "</httpmethods>\n\n";	


    
    # Count of all HTTP Versions...
    #print OUT "$CRLF********** Count of HTTP Versions ********** $CRLF";
    sumhash (\%s6);

    print OUT "<httpversions total=\"$sum\" uniq=\"$uniq\">\n";
    prntx('title', 'Count of HTTP-verssions');
    foreach $k (sort keys %s6 )
    {
	@_ = split "¤", $k;
	print OUT "  <rec>\n";
	prntx('count',$s6{$k});
	prntx('version',$_[0]);
        print OUT "  </rec>\n";
	#printf(OUT "Count: %9d %s  %s %s$CRLF",  $s6{$k}, ($s6{$k}*100/$sum), $_[0]);
	#printf(OUT "  <version count=\"%d\" versionstr=\"%s\"/>\n",  $s6{$k}, $_[0]);
    }
    print OUT "</httpversions>\n\n";
    
    
    # List illegal HTTP Versions...
    sumhash (\%s61);
    
    print OUT "<illegalhttp total=\"$sum\" uniq=\"$uniq\">\n";
    prntx('title', 'Invalid HTTP-versions');
    foreach $k (sort keys %s61 )
    {
	@_ = split "¤", $k;
	print OUT "  <rec>\n";
	prntx('count',$s61{$k});
	prntx('httpstr',$_[0]);
	prntx('srcip',$_[2]);
	prntx('fqdn',resolve($_[2]));
	print OUT "  </rec>\n";
	#printf(OUT "<badhttp count=\"%s\" httpstr=\"%s\" srcip=\"%s\" fqdn=\"%s\" />\n",  $s61{$k}, $_[0], $_[2], resolve($_[2]));
    }
    print OUT "</illegalhttp>\n\n";

    
    # List the Top HIT'ers
    $xx = 1;
    sumhash(\%iptab);
    print OUT "<tophitters total=\"$sum\" uniq=\"$uniq\">\n";
    prntx('title', 'List of Top Hitters');
    #print OUT "$CRLF$CRLF********** Top " . ( ($uniq > $topmax) ? $topmax : $uniq)  . " HIT\'ers **********$CRLF";
    #sumhash (\%iptab);
    #print OUT ($uniq >= $topmax) ? $topmax : $uniq;
    #print OUT "Totally $sum and $uniq unique.$CRLF";
    #printf(OUT "%4s %8s   %7s  %-15s  %-30s$CRLF", 'Rank', '%', 'Count', 'IP', 'FQDN');
    foreach $k (sort {$iptab{$b} <=> $iptab{$a}} keys %iptab )
    {
	@_ = split "¤", $k;
	print OUT " <rec>\n";
	prntx('rank',$xx);
	prntx('count',$iptab{$k});
	prntx('srcip',$_[0]);
	prntx('fqdn',resolve($_[0]));
	#printf(OUT "  <hitter rank=\"%d\" count=\"%d\" srcip=\"%s\" fqdn=\"%s\" />\n", $xx, , $iptab{$k},$_[0], resolve($_[0]));
	print OUT "  </rec>\n";
	if ($xx++ == $topmax) { last; }
    }
    print OUT "</tophitters>\n\n";

    # List attempts to access non-existing pages
    #print OUT "$CRLF$CRLF********** Access attempts generating 403/404 messages **********$CRLF";
    sumhash (\%s01);
    print OUT "<errors4xx total=\"$sum\" uniq=\"$uniq\">\n";
    prntx('title', 'Access attempts generating 4xx errors');
    #print OUT "Totally $sum and $uniq unique.$CRLF";
    #printf(OUT "%7s  %7s  %-15s$CRLF",  'Count', 'Status', 'URL');
    foreach $k (sort {$s01{$b} <=> $s01{$a}} keys %s01 )
    {
	@_ = split "¤", $k;
	print OUT "  <rec>\n";
	prntx('count',$s01{$k});
	prntx('httpstatus',$_[0]);
	#prntx('url',uri_escape($_[1]));
	prntx('url',$_[1]);
	#printf(OUT "  <error4xx count=\"%d\" httpstatus=\"%d\" url=\"%s\" />\n",  $s01{$k}, $_[0], uri_escape($_[1]));
	print OUT " </rec>\n";
    }
    
    print OUT "</errors4xx>\n\n";
    
    
    #Top IP\'s generating 403/404 **********
    $xx = 1;
    sumhash (\%s02);
    print OUT "<top4xxerrorsperip total=\"$sum\" uniq=\"$uniq\">\n";
    prntx('title', 'Top 4xx errors per IP');
    foreach $k (sort {$s02{$b} <=> $s02{$a}} keys %s02 )
    {
	@_ = split "¤", $k;

	#printf(OUT "Count:  %7d  IP: %-15s (%s)$CRLF",  $s02{$k},$_[0], $sip{$_[0]})
	#printf(OUT "  <top4xxerror rank=\"%d\" count=\"%d\" srcip=\"%s\" fqdn=\"%s\" />\n",  $xx, $s02{$k},$_[0], $sip{$_[0]});
	print OUT "  <rec>\n";
	prntx('rank',$xx);
	prntx('count',$s02{$k});
	prntx('srcip',$_[0]);
	prntx('fqdn',$sip{$_[0]});
	print OUT " </rec>\n";	
	if ($xx++ == $topmax) { last; }
    }
    
    print OUT "</top4xxerrorsperip>\n\n";
    
    
    #********** Top $topmax Files per IP genererating 403/404 *********
    $xx = 1;
    sumhash (\%s0);
    print OUT "<top4xxerrorsperipurl total=\"$sum\" uniq=\"$uniq\">\n";
    prntx('title', 'Top 4xx errors per IP and URL');
    #print OUT "Totally $sum and $uniq unique.$CRLF";
    #print OUT "This could inidicate either faultly links on your site, or$CRLF";
    #print OUT "a perpetrator looking for vulnerabilities.$CRLF";
    #printf(OUT "%4s %7s  %-15s  %s$CRLF", 'Rank', 'Count', 'Src IP', 'URL' );
    foreach $k (sort {$s0{$b} <=> $s0{$a}} keys %s0 )
    {
	@_ = split "¤", $k;
	print OUT "  <rec>\n";
	#printf(OUT "  <top4xxerroripurl rank=\"%d\" count=\"%d\" srcip=\"%s\" url=\"%s\" />\n",  $xx, $s0{$k},$_[0], $_[1]);
	prntx('rank',$xx);
	prntx('count',$s0{$k});
	prntx('srcip',$_[0]);
	prntx('url',$_[1]);

	print OUT "  </rec>\n";
	if ($xx++ == $topmax) { last; }
    }
    print OUT "</top4xxerrorsperipurl>\n\n";
	
        
    # 5xx Status
    #print OUT "$CRLF********** Top $topmax IP\'s causing Server Errors (5xx) ********** $CRLF";
    sumhash (\%s42);

    print OUT "<top_5xx_errors_per_ip total=\"$sum\" uniq=\"$uniq\">\n";
    prntx('title', 'Top 5xx errors per IP');
    $xx = 1;
    #print OUT "Totally $sum and $uniq unique.$CRLF";
    #print OUT "This could indicate various attempts to cause your web server$CRLF";
    #print OUT "to produce erronous results.$CRLF";  
    #printf OUT "%7s  %-7s  %-15s %s$CRLF",  'Count', 'Status', 'Src IP', 'FQDN';
    foreach $k (sort {$s42{$b} <=> $s42{$a}} keys %s42 )
    {
	@_ = split "¤", $k;
	print OUT "  <rec>\n";
	#printf(OUT "  <top5xxerrors count=\"%d\" status=\"%d\" srcip=\"%s\" fqdn=\"%s\" />\n",  $s42{$k},$_[0], $_[1], $sip{$_[1]});
	prntx('count',$s42{$k});
	prntx('status',$_[0]);
	prntx('srcip',$_[1]);
	prntx('fqdn',$sip{$_[1]});
	print OUT "  </rec>\n";
	#if ($xx++ == $topmax) { last; }
    }
    
    print OUT "</top_5xx_errors_per_ip>\n\n";
    
    
    # 5xx Status
    #******* Top $topmax URL\'s causing Server Errors (5xx) 
    $xx = 1;
    sumhash (\%s4);
    print OUT "<top_5xx_errors_per_url total=\"$sum\" uniq=\"$uniq\">\n";
    prntx('title', 'Top 5xx errors per URL');
    #print OUT "Totally $sum and $uniq unique.$CRLF";
    #printf OUT "%7s  %-7s  %-20s$CRLF",  'Count', 'Status', 'URL';
    foreach $k (sort {$s4{$b} <=> $s4{$a}} keys %s4 )
    {
	@_ = split "¤", $k;
	print OUT "  <rec>\n";
	#printf(OUT "  <top5xxerrorurl count=\"%d\" status=\"%d\" url=\"%s\" />\n",  $s4{$k},$_[0], $_[1]);
	prntx('count',$s4{$k});
	prntx('status',$_[0]);
	prntx('url',$_[1]);
	print OUT "  </rec>\n";
	if ($xx++ == $topmax) { last; }
    }
    print OUT "</top_5xx_errors_per_url>\n\n"; 


    #print OUT "$CRLF********** Top $topmax URL\'s & IP\'s causing Server Errors (5xx) ********** $CRLF";
    $xx = 1;
    sumhash (\%s41);
    
    print OUT "<top_5xx_errors_per_ip_url total=\"$sum\" uniq=\"$uniq\">\n";  
    prntx('title', 'Top 5xx errors per IP and URL');
    #print OUT "Totally $sum and $uniq unique.$CRLF";
    #printf OUT "%7s  %-7s  %-15s  %s$CRLF", 'Count', 'Status', 'Src IP', 'URL' ;
    foreach $k (sort {$s41{$b} <=> $s41{$a}} keys %s41 )
    {
	@_ = split "¤", $k;
	print OUT "  <rec>\n";
	#printf(OUT "  <top5xxerroripurl count=\"%d\" status=\"%d\" srcip=\"%s\" url=\"%s\" />\n",  $s41{$k},$_[0], $_[2], $_[1]);
	prntx('count',$s41{$k});
	prntx('status',$_[0]);
	prntx('srcip',$_[2]);
	prntx('url',$_[1]);
	print OUT "  </rec>\n";
	#if ($xx++ == $topmax) { last; }
    }

    print OUT "</top_5xx_errors_per_ip_url>\n\n"; 

     
    # Top Referers
    $xx = 1;
    #print OUT "$CRLF********** Top $topmax Referers ********** $CRLF";
    sumhash (\%s11);

    #if ($uniq > 0 ) {
    print OUT "<topreferers total=\"$sum\" uniq=\"$uniq\">\n";
    prntx('title', 'Top Referers');

    foreach $k (sort {$s11{$b} <=> $s11{$a}} keys %s11 )
    {
	@_ = split "¤", $k;
	print OUT "  <rec>\n";
	#$xy = $_[0];
	if ($_[0] =~ m/(.*?)\?(.*)/) {
	    $urlstr = $1; $uristr = uri_escape($2);
	} else {
	    #print "$_[0]\n";
	    $urlstr = $_[0]; $uristr = '';
	}

	#$xy =~ s/\?.*//i;
	#printf(OUT "  <refstr count=\"%d\"  refurl=\"%s\" refuri=\"%s\" />\n",  $s11{$k}, $urlstr, $uristr );
	prntx('count',$s11{$k});
	prntx('refurl',$urlstr);
	prntx('refuri',$uristr);
	print OUT "  </rec>\n";
	#if ($xx++ == $topmax) { last; }
    }
    print OUT "</topreferers>\n\n"; 

    
    # Top Browsers
    $xx = 1;
    sumhash (\%s12);
    print OUT "<topbrowsers total=\"$sum\" uniq=\"$uniq\">\n";   
    prntx('title', 'Top Browsers used');
    #print OUT "Totally $sum and $uniq unique.$CRLF";
    #printf OUT "%7s  %-50s$CRLF", 'Count', 'Browser' ;
    foreach $k (sort {$s12{$b} <=> $s12{$a}} keys %s12 )
    {
	@_ = split "¤", $k;
	print OUT "  <rec>\n"; 
	#printf(OUT "  <topbrows count=\"%d\" browser=\"%s\" />\n",  $s12{$k}, uri_escape($_[0]));
	prntx('count',$s12{$k});
	prntx('browser',uri_escape($_[0]));
	print OUT "  </rec>\n";
	#if ($xx++ == $topmax) { last; }
    }
    
    print OUT "</topbrowsers>\n\n";

    # Check for Cookie Manipulation
    $xx = 1;
    sumhash (\%s14);

    print OUT "<cookiemanip total=\"$sum\" uniq=\"$uniq\">\n";
    prntx('title', 'Suspected Cookie Manipulation');
    #print OUT "Totally $sum and $uniq unique. Showing at maximum the top $topmax.$CRLF";
    #print OUT "This could inidicate attempted session hijacking,$CRLF";
    #print OUT "or users coming via a non-ip session aware proxy.$CRLF";
    #printf OUT "%9s %-15s %s$CRLF", 'Count', 'IP', 'FQDN';
    #foreach $k (sort {$s14{$b} <=> $s14{$a}} keys %s14)
    $old = '';
    foreach $k (sort keys %s14)
    {
	@_ = split "¤", $k;
	if ($old ne $_[0]) {
	    #print OUT "$CRLF";
	    #$co = $cookie;
	    $co = (length($_[0]) > 60) ? substr($_[0],0,20) . ".. [ Truncated ] .." . substr($_[0], length($$_[0])-20,20) : $_[0];
	    printf OUT "  <cookie str=\"%s\" />\n", $co;
	}
	printf OUT "    <cookieinfo count=\"%d\" srcip=\"%s\" fqdn=\"%s\"/>\n", $s14{$k}, $_[1], resolve($_[1]);
	
	
	$old = $_[0];
	#if ($xx++ == $topmax) { last; }
    }
    print OUT "</cookiemanip>\n\n";
    

    # Check for Directory scanning / Listing
    $xx = 1;
    sumhash (\%s15);
    print OUT "<subdirlist total=\"$sum\" uniq=\"$uniq\">\n";
    prntx('title', 'Subdirectory Listing Attempts');
    foreach $k (sort {$s15{$b} <=> $s15{$a}} keys %s15)
    {
	@_ = split "¤", $k;
	print OUT "  <rec>\n";
	#printf(OUT "  <listing count=\"%d\" status=\"%s\" url=\"%s\" srcip=\"%s\" fqdn=\"%s\" />\n",  $s15{$k},$_[2], uri_escape($_[1]), $_[0], resolve($_[0]));
	prntx('count',$s15{$k});
	prntx('status',$_[2]);
	prntx('url',$_[1]);
	prntx('srcip',$_[0]);
	prntx('fqdn',resolve($_[0]));
	print OUT "  </rec>\n";
	#if ($xx++ == $topmax) { last; }
    }
    print OUT "</subdirlist>\n\n";
    

    # List attempted form manipulation
    $xx = 1;
    sumhash (\%s16);

    print OUT "<formmanip total=\"$sum\" uniq=\"$uniq\">\n";
    prntx('title', 'List suspected FORM manipulation');
    foreach $k (sort {$s16{$b} <=> $s16{$a}} keys %s16)
    {
	@_ = split "¤", $k;
	print OUT "  <rec>\n";
	#printf(OUT "  <formstr count=\"%d\" query=\"%s\" srcip=\"%s\" fqdn=\"%s\" />\n",  $s16{$k}, uri_escape($_[1]), $_[0], resolve($_[0]));
	prntx('count',$s16{$k});
	prntx('query',$_[1]);
	prntx('srcip',$_[0]);
	prntx('fqdn',resolve($_[0]));
	print OUT "  </rec>\n";
	#if ($xx++ == $topmax) { last; }
    }
    print OUT "</formmanip>\n\n";

    # List attempted Anonymous Proxy Scans
    $xx = 1;
    #print OUT "$CRLF********** Attempts to locate Proxy ********** $CRLF";
    sumhash (\%s17);
    print OUT "<locateproxy total=\"$sum\" uniq=\"$uniq\">\n";
    prntx('title', 'Attempts to locate Proxy');
    #print OUT "Totally $sum and $uniq unique.$CRLF";
    #print OUT "Successfull attempts could indicate that your web server can$CRLF";
    #print OUT "be used for staging Internet Attacks and fraud.$CRLF";
    #printf OUT "%7s %6s %-40s %-15s %-15s %s$CRLF", 'Count', 'Status', 'URL', 'IP', 'FQDN';
    foreach $k (sort {$s17{$b} <=> $s17{$a}} keys %s17)
    {
	@_ = split "¤", $k;
	print OUT "  <rec>\n";
	#printf(OUT "  <locprox count=\"%d\" status=\"%d\" url=\"%s\" srcip=\"%s\" fqdn=\"%s\" />\n",  $s17{$k}, $_[1], $_[2], $_[0], resolve($_[0]));
	prntx('count', $s17{$k});
	prntx('status', $_[1]);
	prntx('url', $_[2]);
	prntx('srcip',$_[0]);
	prntx('fqdn',resolve($_[0]));

	print OUT "  </rec>\n";
	if ($xx++ == $topmax) { last; }
    }
    print OUT "</locateproxy>\n\n";


    # List exceedingly Long URL's
    $xx = 1;
    sumhash (\%s18);
    print OUT "<longurlattempt total=\"$sum\" uniq=\"$uniq\">\n";
    prntx('title', 'Exceedingly Long URLs');
    #print OUT "These could indicate attempts to locate and use Buffer Overflows$CRLF";
    #print OUT "to compromise the Web Server, and shoud be considererd as serious attempts to breach Security.$CRLF";
    #printf OUT "%7s %6s %10s  %-15s %-30s %-15s$CRLF", 'Count', 'Status', 'Length', 'URL', 'FQDN' ;
    foreach $k (sort {$s18{$b} <=> $s18{$a}} keys %s18)
    {
	@_ = split "¤", $k;
	print OUT "  <rec>\n";
	#printf(OUT "<longurl count=\"%d\" status=\"%s\" length=\"%s\" url=\"%s\" srcip=\"%s\" fqdn=\"%s\" />\n  $CRLF",  $s18{$k}, $_[3], $_[2], $_[0] , $_[1], resolve($_[1]));
	prntx('count',$s18{$k});
	prntx('status',$_[3]);
	prntx('length',$_[2]);
	prntx('url',$_[0]);
	prntx('srcip',$_[1]);
	prntx('fqdn',resolve($_[1]));
	
	print OUT "  </rec>\n";
	if ($xx++ == $topmax) { last; }
    }
    
    print OUT "</longurlattempt>\n\n"; 
    
    print OUT "</report>\n";
    
    close OUT;


}




sub printall {

    # Check if results are OK, before mailing report
    if ($numlines eq $logformat{'Unknown'}) {
	exit 99;
    }
    slog('Printing text output');
    print OUT "Security Log File Analysis$CRLF";
    print OUT "SLAC v $VERSION$CRLF$CRLF";
    print OUT "Inputfile(s): " . join (" ",@list). "$CRLF";
    #print OUT "Outputfile: $outfile $CRLF";
    print OUT "Log Start: $mindate$CRLF";
    print OUT "Log Stopp: $maxdate$CRLF";
    #print OUT "Execution started: " . $starttimetext . "$CRLF";
    #print OUT "Execution stopped: " . localtime() . "$CRLF";
    printf OUT "nr of analyzed rows:        %7d $CRLF", $numlines;
    #printf OUT "nr of non-analyzed rows:    %7d $CRLF", $logformat{'UNKNOWN'};
    printf OUT "nr of unique IP-addresses:  %7d $CRLF", $numip;
    print OUT "Rows identified as:$CRLF";
    foreach $x (keys %logformat) {
	printf OUT " %-24s %9d$CRLF", $x, $logformat{$x};
    }

    slog("Nr of Analyzed rows: $numlines");
    slog("Rows/sec: " . $numlines / (time - $starttime + 1));
    #printf OUT "nr of analyzed rows/second: %7d $CRLF", $numlines / (time - $starttime + 1);
    #printf OUT "nr of $logformat{'CLF'}\n";
    
    if ($opt_N ne '') 
    {  print OUT "Name Resolution has NOT been performed.$CRLF$CRLF"; }
    #else
    #{  print OUT "Name Resolution has been performed.$CRLF$CRLF"; }

    sumhash (\%s20);
    if ($sum gt 0) {
	print OUT "Servers analyzed:$CRLF";
	foreach $x (keys %s20 ) {
	    printf OUT "  %-15s %9d$CRLF", $x, $s20{$x};
	}
    }

    
    # Show number of hits/hour
    print OUT "$CRLF********** Hits / hour ********** $CRLF";
    sumhash (\%s7);
    #print OUT "Totally $sum and $uniq unique.$CRLF";
    printf OUT "%7s  %9s$CRLF",  'Hour', 'Hits';
    #foreach $k (sort keys %s7)
    for ($k=0;$k<24;$k++)
    {
	@_ = split "¤", $k;
	$hits = $s7{sprintf("%02d", $k)};
	if ($hits eq '') { $hits = '0'};
	printf (OUT "%7d  %9s  %-50s$CRLF",  $_[0], $hits, "*" x ($hits / ($hrmax+1) * 40));
    }
    



    # Dangerous files...
    print OUT "$CRLF********** Successful attempts to retrieve \'Dangerous\' files ********** $CRLF";
    sumhash (\%s3);
    if ($uniq gt 0) {
	print OUT "This could inidicate a serious security breach.$CRLF";
	print OUT "Totally $sum and $uniq unique.$CRLF";
	printf OUT "%7s  %-15s  %-50s$CRLF",  'Count', 'Src IP', 'URL' ;
	foreach $k (sort {$s3{$b} <=> $s3{$a}} keys %s3 )
	{
	    @_ = split "¤", $k;
	    printf (OUT "%7d  %-15s  %-50s$CRLF",  $s3{$k},$_[0], $_[1]);
	}
    } else {
	printf OUT "None. $CRLF";
    }
    
    # Unauthorized
    print OUT "$CRLF********** Users who have accessed protected pages ********** $CRLF";
    sumhash (\%s2);
    if ($uniq gt 0) {
	print OUT "Totally $sum and $uniq unique.$CRLF";
	printf OUT  "%7s  %5s  %-15s  %-9s %s$CRLF", 'Count', 'Status', 'Src IP', 'User', 'URL';
	foreach $k (sort {$s2{$b} <=> $s2{$a}} keys %s2 )
	{
	    @_ = split "¤", $k;
	    printf(OUT  "%7d  %5s   %-15s  %-9s %s$CRLF",  $s2{$k},$_[0], $_[1], $_[3], $_[2]);
	}
    } else {
	printf OUT "None. $CRLF";
    }

    
    print OUT "$CRLF********** Logged in Users **********$CRLF";
    sumhash (\%s10);
    if ($uniq gt 0) {   
	print OUT "Totally $sum and $uniq unique.$CRLF";
	printf(OUT "%9s  %-15s$CRLF",  'Count', 'User');
	foreach $k (sort {$s10{$b} <=> $s10{$a}} keys %s10 )
	{
	    @_ = split "¤", $k;
	    printf(OUT "%9d  %-15s$CRLF",  $s10{$k},$_[0]);
	}
    } else {
        printf OUT "None. $CRLF";
    }

    print OUT "$CRLF********** Logged in users per IP-address (excl Anonymous) **********$CRLF";
    sumhash (\%s1);
    if ($uniq gt 0) {
	print OUT "Totally $sum and $uniq unique.$CRLF";
	printf OUT "%9s  %-15s  %-15s  %s$CRLF",  'Count', 'User', 'Src-IP', 'FQDN';
	foreach $k (sort {$s1{$b} <=> $s1{$a}} keys %s1 )
	{
	    @_ = split "¤", $k;
	    printf OUT "%9d  %-15s  %-15s  %s$CRLF",  $s1{$k},$_[0], $_[1], $sip{$_[1]};
	}
    } else {
        printf OUT "None. $CRLF";
    }
    
    # Count of all Statuscodes...
    print OUT "$CRLF********** Count of HTTP statuscodes ********** $CRLF";
    sumhash (\%s5);
    
    print OUT "Totally $sum and $uniq unique.$CRLF";
    print OUT "    Count     ( % )     HTTP-Status $CRLF";
    foreach $k (sort keys %s5 )
    {
	@_ = split "¤", $k;
	#printf(OUT "Count: %9d (%6.2f%%) HTTP Status: %-4d  %s$CRLF",  $s5{$k},($s5{$k}*100/$sum), $_[0], $STATCODE{$_[0]});
	printf(OUT "%9d (%6.2f%%)    %4s %s$CRLF",  $s5{$k},($s5{$k}*100/$sum), $_[0], $STATCODE{$_[0]});
    }

    # Count of all HTTP Methods...
    print OUT "$CRLF********** Count of HTTP Methods ********** $CRLF";
    sumhash (\%s19);
    print OUT "Totally $sum and $uniq unique.$CRLF";
    print OUT "    Count     ( % )     HTTP-Method $CRLF";
    foreach $k (sort {$s19{$b} <=> $s19{$a}} keys %s19 )
    {
        @_ = split "¤", $k;
	printf(OUT "%9d (%6.2f%%)     %s$CRLF",  $s19{$k}, ($s19{$k}*100/$sum),    $k,);
}


    
    # Count of all HTTP Versions...
    print OUT "$CRLF********** Count of HTTP Versions ********** $CRLF";
    sumhash (\%s6);
    print OUT "Totally $sum and $uniq unique.$CRLF";
    print OUT "    Count     ( % )    HTTP-Version $CRLF";
    foreach $k (sort {$s6{$b} <=> $s6{$a}} keys %s6 )
    {
	@_ = split "¤", $k;
	#printf(OUT "Count: %9d %s  %s %s$CRLF",  $s6{$k}, ($s6{$k}*100/$sum), $_[0]);
	printf(OUT "%9d (%6.2f%%)    %s$CRLF",  $s6{$k}, ($s6{$k}*100/$sum), $_[0]);
    }
    
    # List illegal HTTP Versions...
    print OUT "$CRLF********** List illegal HTTP Versions ********** $CRLF";
    sumhash (\%s61);
    if ($uniq gt 0) {
	print OUT "This could inidicate attempts to manipulate and compromise the webserver.$CRLF";
	print OUT "Totally $sum and $uniq unique.$CRLF";
	printf(OUT "%9s %-25s %-15s %s %-s$CRLF", 'Count' , 'HTTP String',  'IP', 'FQDN');
	foreach $k (sort {$s61{$b} <=> $s61{$a}} keys %s61 )
	{
	    @_ = split "¤", $k;
	    printf(OUT "%9s %-25s %-15s %s  %s$CRLF",  $s61{$k}, $_[0], $_[2], resolve($_[2]));
	}
    } else {
	printf OUT "None. $CRLF";
    }

    # List the Top HIT'ers
    $xx = 1;
    sumhash(\%iptab);
    print OUT "$CRLF$CRLF********** Top " . ( ($uniq > $topmax) ? $topmax : $uniq)  . " HIT\'ers **********$CRLF";
    #sumhash (\%iptab);
    #print OUT ($uniq >= $topmax) ? $topmax : $uniq;
    print OUT "Totally $sum and $uniq unique.$CRLF";
    printf(OUT "%4s %8s   %7s  %-15s  %-30s$CRLF", 'Rank', '%', 'Count', 'IP', 'FQDN');
    foreach $k (sort {$iptab{$b} <=> $iptab{$a}} keys %iptab )
    {
	@_ = split "¤", $k;
	printf(OUT "%4d (%6.2f%%)  %7d  %-15s  %-30s$CRLF", $xx, ($iptab{$k}*100/$sum), $iptab{$k},$_[0], resolve($_[0]));
	if ($xx++ == $topmax) { last; }
    }
    
    
    # List attempts to access non-existing pages
    print OUT "$CRLF$CRLF********** Access attempts generating 403/404 messages **********$CRLF";
    
    sumhash (\%s01);
    if ($uniq gt 0) {
	print OUT "Totally $sum and $uniq unique.$CRLF";
	printf(OUT "%7s  %7s  %-15s$CRLF",  'Count', 'Status', 'URL');
	foreach $k (sort {$s01{$b} <=> $s01{$a}} keys %s01 )
	{
	    @_ = split "¤", $k;
	    printf(OUT "%7d  %7d  %-15s$CRLF",  $s01{$k},$_[0], $_[1]);
	}
	
	print OUT "$CRLF$CRLF********** Top $topmax IP\'s generating 403/404 **********$CRLF";
	$xx = 1;
	sumhash (\%s02);
	print OUT "Totally $sum and $uniq unique.$CRLF";
	print OUT "The top IP's on this list could be the source for vulnerability scans of your  site.$CRLF";
	printf(OUT "%4s %7s   %-15s  %s$CRLF",  'Rank', "Count", "IP-Address", "FQDN");
	foreach $k (sort {$s02{$b} <=> $s02{$a}} keys %s02 )
	{
	    @_ = split "¤", $k;
	    #printf(OUT "Count:  %7d  IP: %-15s (%s)$CRLF",  $s02{$k},$_[0], $sip{$_[0]})
	    printf(OUT "%4d %7d   %-15s  %s$CRLF",  $xx, $s02{$k},$_[0], $sip{$_[0]});
	    if ($xx++ == $topmax) { last; }
	}
	
	print OUT "$CRLF$CRLF********** Top $topmax Files per IP genererating 403/404 **********$CRLF";
	$xx = 1;
	sumhash (\%s0);
	print OUT "Totally $sum and $uniq unique.$CRLF";
	print OUT "This could inidicate either faultly links on your site, or$CRLF";
	print OUT "a perpetrator looking for vulnerabilities.$CRLF";
	printf(OUT "%4s %7s  %-15s  %s$CRLF", 'Rank', 'Count', 'Src IP', 'URL' );
	foreach $k (sort {$s0{$b} <=> $s0{$a}} keys %s0 )
	{
	    @_ = split "¤", $k;
	    printf(OUT "%4d %7d  %-15s  %s$CRLF",  $xx, $s0{$k},$_[0], $_[1]);
	    if ($xx++ == $topmax) { last; }
	}
    } else {
        printf OUT "None. $CRLF";
    }
    
	
    
    # 5xx Status
    print OUT "$CRLF********** Top $topmax IP\'s causing Server Errors (5xx) ********** $CRLF";
    sumhash (\%s42);
    if ($uniq > 0) {
	$xx = 1;
	print OUT "Totally $sum and $uniq unique.$CRLF";
	print OUT "This could indicate various attempts to cause your web server$CRLF";
	print OUT "to produce erronous results.$CRLF";  
	printf OUT "%7s  %-7s  %-15s %s$CRLF",  'Count', 'Status', 'Src IP', 'FQDN';
	foreach $k (sort {$s42{$b} <=> $s42{$a}} keys %s42 )
	{
	    @_ = split "¤", $k;
	    printf(OUT "%7d  %-7d  %-15s %s$CRLF",  $s42{$k},$_[0], $_[1], $sip{$_[1]});
	    if ($xx++ == $topmax) { last; }
	}
   
    
	# 5xx Status
	print OUT "$CRLF********** Top $topmax URL\'s causing Server Errors (5xx) ********** $CRLF";
	$xx = 1;
	sumhash (\%s4);
	print OUT "Totally $sum and $uniq unique.$CRLF";
	printf OUT "%7s  %-7s  %-20s$CRLF",  'Count', 'Status', 'URL';
	foreach $k (sort {$s4{$b} <=> $s4{$a}} keys %s4 )
	{
	    @_ = split "¤", $k;
	    printf(OUT "%7d  %-7d  %-20s$CRLF",  $s4{$k},$_[0], $_[1]);
	    if ($xx++ == $topmax) { last; }
	}
	
	print OUT "$CRLF********** Top $topmax URL\'s & IP\'s causing Server Errors (5xx) ********** $CRLF";
	$xx = 1;
	sumhash (\%s41);
	print OUT "Totally $sum and $uniq unique.$CRLF";
	printf OUT "%7s  %-7s  %-15s  %s$CRLF", 'Count', 'Status', 'Src IP', 'URL' ;
	foreach $k (sort {$s41{$b} <=> $s41{$a}} keys %s41 )
	{
	    @_ = split "¤", $k;
	    printf(OUT "%7d  %-7d  %-15s  %s$CRLF",  $s41{$k},$_[0], $_[2], $_[1]);
	    if ($xx++ == $topmax) { last; }
	}
    } else {
        printf OUT "None. $CRLF";
    }
 
    # Top Referers
    $xx = 1;
    print OUT "$CRLF********** Top $topmax Referers ********** $CRLF";
    sumhash (\%s11);
    if ($uniq > 0 ) {
	print OUT "Totally $sum and $uniq unique.$CRLF";
	printf OUT "%7s  %-50s$CRLF", 'Count', 'Referer' ;
	foreach $k (sort {$s11{$b} <=> $s11{$a}} keys %s11 )
	{
	    @_ = split "¤", $k;
	    printf(OUT "%7d  %-50s $CRLF",  $s11{$k},$_[0]);
	    if ($xx++ == $topmax) { last; }
	}
    } else {
	printf OUT "Not Available$CRLF";
    }
    
    # Top Browsers
    $xx = 1;
    print OUT "$CRLF********** Top $topmax Browsers ********** $CRLF";      
    sumhash (\%s12);
    if ($uniq > 0 ) {
	print OUT "Totally $sum and $uniq unique.$CRLF";
	printf OUT "%7s  %-50s$CRLF", 'Count', 'Browser' ;
	foreach $k (sort {$s12{$b} <=> $s12{$a}} keys %s12 )
	{
	    @_ = split "¤", $k;
	    printf(OUT "%7d  %-50s $CRLF",  $s12{$k},$_[0]);             
	    if ($xx++ == $topmax) { last; }
	}
    } else {
	printf OUT "Not Available$CRLF";
    }

    # Check for Cookie Manipulation
    $xx = 1;
    print OUT "$CRLF********** Same Cookie from different IP-addresses ********** $CRLF";
    sumhash (\%s14);
    if ($uniq gt 0) {
	print OUT "Totally $sum and $uniq unique. Showing at maximum the top $topmax.$CRLF";
	print OUT "This could inidicate attempted session hijacking,$CRLF";
	print OUT "or users coming via a non-ip session aware proxy.$CRLF";
	printf OUT "%9s %-15s %s$CRLF", 'Count', 'IP', 'FQDN';
	#foreach $k (sort {$s14{$b} <=> $s14{$a}} keys %s14)
	$old = '';
	foreach $k (sort keys %s14)
	{
	    #print "\$k: $k\n";
	    @_ = split "¤", $k;
	    #print "\$_\[0\]:$_[0]$CRLF";
	    if ($old ne $_[0]) {
		print OUT "$CRLF";
		#$co = $cookie;
		$co = (length($_[0]) > 60) ? substr($_[0],0,20) . ".. [ Truncated ] .." . substr($_[0], length($$_[0])-20,20) : $_[0];
		    
		printf OUT "Cookie: %s$CRLF", $co;
	    }
	    printf OUT "%9d %-15s %s$CRLF", $s14{$k}, $_[1], resolve($_[1]);
	    
	    $old = $_[0];
	    #if ($xx++ == $topmax) { last; }
	}
    } else {
	print OUT "None found.$CRLF";
    }

    # Check for Directory scanning / Listing
    $xx = 1;
    print OUT "$CRLF********** Unsuccessful Subdirectory Listing Attempts ********** $CRLF";
    sumhash (\%s15);
    if ($uniq gt 0) {
        print OUT "Totally $sum and $uniq unique.$CRLF";
        #print OUT "This could inidicate attempted session hijacking.$CRLF";
        printf OUT "%7s %7s %-40s %-15s %-4s$CRLF", 'Count', 'Status', 'URL', 'IP', 'FQDN';
        foreach $k (sort {$s15{$b} <=> $s15{$a}} keys %s15)
        {
            @_ = split "¤", $k;
            printf(OUT "%7d %7s %-40s %-15s %s$CRLF",  $s15{$k},$_[2], $_[1], $_[0], resolve($_[0]));
            if ($xx++ == $topmax) { last; }
        }


	print OUT "$CRLF********** Unsuccessful Subdir attempts per IP ********$CRLF";
	foreach $k (sort {$s151{$b} <=> $s151{$a}} keys %s151) 
	{
	    printf(OUT "Count: %-10s IP: %-15s$CRLF", $s151{$k}, $k);
	    foreach $l (keys %s15) {
		($ip2, $url2, $status2) = split "¤", $l;
		if ($ip2 eq "$k") {
		    printf OUT "  Subdir: %7s  %4d  %s $CRLF", $s15{$l}, $status2, $url2;
		    
		} 
	    }
	    print OUT "$CRLF";
	}

    } else {
        print OUT "None found.$CRLF";
    }



    # List attempted form manipulation
    $xx = 1;
    print OUT "$CRLF********** Suspected Form Data Manipulation ********** $CRLF";
    sumhash (\%s16);
    if ($uniq gt 0) {
        print OUT "Totally $sum and $uniq unique.$CRLF";
        print OUT "This could inidicate attempted unauthorized database access.$CRLF";
        printf OUT "%7s %-30s %-15s %-15s %-20s$CRLF", 'Count', 'Query', 'IP', 'FQDN' ;
        foreach $k (sort {$s16{$b} <=> $s16{$a}} keys %s16)
        {
            @_ = split "¤", $k;
            printf(OUT "%7d %-30s %-15s %-15s$CRLF",  $s16{$k}, $_[1], $_[0], resolve($_[0]));
            if ($xx++ == $topmax) { last; }
        }
    } else {
        print OUT "None found.$CRLF";
    }

    # List attempted Anonymous Proxy Scans
    $xx = 1;
    print OUT "$CRLF********** Attempts to locate Proxy ********** $CRLF";
    sumhash (\%s17);
    if ($uniq gt 0) {
        print OUT "Totally $sum and $uniq unique.$CRLF";
        print OUT "Successfull attempts could indicate that your web server can$CRLF";
	print OUT "be used for staging Internet Attacks and fraud.$CRLF";
        printf OUT "%7s %6s %-40s %-15s %-15s %s$CRLF", 'Count', 'Status', 'URL', 'IP', 'FQDN';
        foreach $k (sort {$s17{$b} <=> $s17{$a}} keys %s17)
        {
            @_ = split "¤", $k;
            printf(OUT "%7d %6d %-40s %-15s %s$CRLF",  $s17{$k}, $_[1], $_[2], $_[0], resolve($_[0]));
            if ($xx++ == $topmax) { last; }
        }
    } else {
        print OUT "None found.$CRLF";
    }

    # List exceedingly Long URL's
    $xx = 1;
    print OUT "$CRLF********** Exceedingly Long URL's ********** $CRLF";
    sumhash (\%s18);
    if ($uniq gt 0) {
        print OUT "Totally $sum and $uniq unique.$CRLF";
        print OUT "These could indicate attempts to locate and use Buffer Overflows$CRLF";
        print OUT "to compromise the Web Server, and shoud be considererd as serious attempts to breach Security.$CRLF";
        printf OUT "%7s %6s %10s  %-15s %-30s %-15s$CRLF", 'Count', 'Status', 'Length', 'URL', 'FQDN' ;
        foreach $k (sort {$s18{$b} <=> $s18{$a}} keys %s18)
        {
            @_ = split "¤", $k;
            printf(OUT "%7d %6s %10s  %-30s\n%26s %-15s %s $CRLF",  $s18{$k}, $_[3], $_[2], $_[0] ,'', $_[1], resolve($_[1]));
	    if ($xx++ == $topmax) { last; }
	}
    } else {
	print OUT "None found.$CRLF";
    }
    
    close OUT;
}


sub printhtml {

    # Check if results are OK, before mailing report
    if ($numlines eq $logformat{'Unknown'}) {
	exit 99;
    }
    slog('Printing text output');
    print OUT "Security Log File Analysis$CRLF";
    print OUT "SLAC v $VERSION$CRLF$CRLF";
    print OUT "Inputfile(s): " . join (" ",@list). "$CRLF";
    #print OUT "Outputfile: $outfile $CRLF";
    print OUT "Log Start: $mindate$CRLF";
    print OUT "Log Stopp: $maxdate$CRLF";
    #print OUT "Execution started: " . $starttimetext . "$CRLF";
    #print OUT "Execution stopped: " . localtime() . "$CRLF";
    printf OUT "nr of analyzed rows:        %7d $CRLF", $numlines;
    #printf OUT "nr of non-analyzed rows:    %7d $CRLF", $logformat{'UNKNOWN'};
    printf OUT "nr of unique IP-addresses:  %7d $CRLF", $numip;
    print OUT "Rows identified as:$CRLF";
    foreach $x (keys %logformat) {
	printf OUT " %-24s %9d$CRLF", $x, $logformat{$x};
    }

    slog("Nr of Analyzed rows: $numlines");
    slog("Rows/sec: " . $numlines / (time - $starttime + 1));
    #printf OUT "nr of analyzed rows/second: %7d $CRLF", $numlines / (time - $starttime + 1);
    #printf OUT "nr of $logformat{'CLF'}\n";
    
    if ($opt_N ne '') 
    {  print OUT "Name Resolution has NOT been performed.$CRLF$CRLF"; }
    #else
    #{  print OUT "Name Resolution has been performed.$CRLF$CRLF"; }
    
    # Show number of hits/hour
    print OUT "$CRLF********** Hits / hour ********** $CRLF";
    sumhash (\%s7);
    #print OUT "Totally $sum and $uniq unique.$CRLF";
    printf OUT "%7s  %9s$CRLF",  'Hour', 'Hits';
    #foreach $k (sort keys %s7)
    for ($k=0;$k<24;$k++)
    {
	@_ = split "¤", $k;
	$hits = $s7{sprintf("%02d", $k)};
	if ($hits eq '') { $hits = '0'};
	printf (OUT "%7d  %9s  %-50s$CRLF",  $_[0], $hits, "*" x ($hits / ($hrmax+1) * 40));
    }
    


    # Show number of hits/hour in PNG format

    #my $data = GD::Graph::Data->new();
    #my $name = '/usr/local/apache/htdocs/toptalk';
    #print OUT "$CRLF********** Hits / hour ********** $CRLF";
    #sumhash (\%s7);
    #for ($k=0;$k<24;$k++)
    #{
#	$hits = $s7{sprintf("%02d", $k)};
#        if ($hits eq '') { $hits = '0'};
#	$data->add_point($k, $hits);
#}
    #my $my_graph = GD::Graph::bars->new();
    #$my_graph->set(x_label  => 'Hour',
#		   y_label  => 'Hits',
#		   title           => "Hits per hour, $mindate",
#		   y_max_value     => $max,
#		   y_tick_number   => 8,
#		   y_label_skip    => 2,
#		   #x_labels_vertical => 1,
#		   # shadows
#		   bar_spacing     => 8,
#		   shadow_depth    => 2,
#		   shadowclr       => 'dred',
#      		   transparent     => 0,
#		   )
#	or warn $my_graph->error;

    #$my_graph->plot($data) or die $my_graph->error;
    #save_chart($my_graph, $name);


    # Dangerous files...
    print OUT "$CRLF********** Successful attempts to retrieve \'Dangerous\' files ********** $CRLF";
    sumhash (\%s3);
    if ($uniq gt 0) {
	print OUT "This could inidicate a serious security breach.$CRLF";
	print OUT "Totally $sum and $uniq unique.$CRLF";
	printf OUT "%7s  %-15s  %-50s$CRLF",  'Count', 'Src IP', 'URL' ;
	foreach $k (sort {$s3{$b} <=> $s3{$a}} keys %s3 )
	{
	    @_ = split "¤", $k;
	    printf (OUT "%7d  %-15s  %-50s$CRLF",  $s3{$k},$_[0], $_[1]);
	}
    } else {
	printf OUT "None. $CRLF";
    }
    
    # Unauthorized
    print OUT "$CRLF********** Users who have accessed protected pages ********** $CRLF";
    sumhash (\%s2);
    if ($uniq gt 0) {
	print OUT "Totally $sum and $uniq unique.$CRLF";
	printf OUT  "%7s  %5s  %-15s  %-9s %s$CRLF", 'Count', 'Status', 'Src IP', 'User', 'URL';
	foreach $k (sort {$s2{$b} <=> $s2{$a}} keys %s2 )
	{
	    @_ = split "¤", $k;
	    printf(OUT  "%7d  %5s   %-15s  %-9s %s$CRLF",  $s2{$k},$_[0], $_[1], $_[3], $_[2]);
	}
    } else {
	printf OUT "None. $CRLF";
    }

    
    print OUT "$CRLF********** Logged in Users **********$CRLF";
    sumhash (\%s10);
    if ($uniq gt 0) {   
	print OUT "Totally $sum and $uniq unique.$CRLF";
	printf(OUT "%9s  %-15s$CRLF",  'Count', 'User');
	foreach $k (sort {$s10{$b} <=> $s10{$a}} keys %s10 )
	{
	    @_ = split "¤", $k;
	    printf(OUT "%9d  %-15s$CRLF",  $s10{$k},$_[0]);
	}
    } else {
        printf OUT "None. $CRLF";
    }

    print OUT "$CRLF********** Logged in users per IP-address (excl Anonymous) **********$CRLF";
    sumhash (\%s1);
    if ($uniq gt 0) {
	print OUT "Totally $sum and $uniq unique.$CRLF";
	printf OUT "%9s  %-15s  %-15s  %s$CRLF",  'Count', 'User', 'Src-IP', 'FQDN';
	foreach $k (sort {$s1{$b} <=> $s1{$a}} keys %s1 )
	{
	    @_ = split "¤", $k;
	    printf OUT "%9d  %-15s  %-15s  %s$CRLF",  $s1{$k},$_[0], $_[1], $sip{$_[1]};
	}
    } else {
        printf OUT "None. $CRLF";
    }
    
    # Count of all Statuscodes...
    print OUT "$CRLF********** Count of HTTP statuscodes ********** $CRLF";
    sumhash (\%s5);
    
    print OUT "Totally $sum and $uniq unique.$CRLF";
    print OUT "    Count     ( % )     HTTP-Status $CRLF";
    foreach $k (sort keys %s5 )
    {
	@_ = split "¤", $k;
	#printf(OUT "Count: %9d (%6.2f%%) HTTP Status: %-4d  %s$CRLF",  $s5{$k},($s5{$k}*100/$sum), $_[0], $STATCODE{$_[0]});
	printf(OUT "%9d (%6.2f%%)    %4s %s$CRLF",  $s5{$k},($s5{$k}*100/$sum), $_[0], $STATCODE{$_[0]});
    }

    # Count of all HTTP Methods...
    print OUT "$CRLF********** Count of HTTP Methods ********** $CRLF";
    sumhash (\%s19);
    print OUT "Totally $sum and $uniq unique.$CRLF";
    print OUT "    Count     ( % )     HTTP-Method $CRLF";
    foreach $k (sort {$s19{$b} <=> $s19{$a}} keys %s19 )
    {
        @_ = split "¤", $k;
	printf(OUT "%9d (%6.2f%%)     %s$CRLF",  $s19{$k}, ($s19{$k}*100/$sum),    $k,);
}


    
    # Count of all HTTP Versions...
    print OUT "$CRLF********** Count of HTTP Versions ********** $CRLF";
    sumhash (\%s6);
    print OUT "Totally $sum and $uniq unique.$CRLF";
    print OUT "    Count     ( % )    HTTP-Version $CRLF";
    foreach $k (sort {$s6{$b} <=> $s6{$a}} keys %s6 )
    {
	@_ = split "¤", $k;
	#printf(OUT "Count: %9d %s  %s %s$CRLF",  $s6{$k}, ($s6{$k}*100/$sum), $_[0]);
	printf(OUT "%9d (%6.2f%%)    %s$CRLF",  $s6{$k}, ($s6{$k}*100/$sum), $_[0]);
    }
    
    # List illegal HTTP Versions...
    print OUT "$CRLF********** List illegal HTTP Versions ********** $CRLF";
    sumhash (\%s61);
    if ($uniq gt 0) {
	print OUT "This could inidicate attempts to manipulate and compromise the webserver.$CRLF";
	print OUT "Totally $sum and $uniq unique.$CRLF";
	printf(OUT "%9s %-25s %-15s %s %-s$CRLF", 'Count' , 'HTTP String',  'IP', 'FQDN');
	foreach $k (sort {$s61{$b} <=> $s61{$a}} keys %s61 )
	{
	    @_ = split "¤", $k;
	    printf(OUT "%9s %-25s %-15s %s  %s$CRLF",  $s61{$k}, $_[0], $_[2], resolve($_[2]));
	}
    } else {
	printf OUT "None. $CRLF";
    }

    # List the Top HIT'ers
    $xx = 1;
    sumhash(\%iptab);
    print OUT "$CRLF$CRLF********** Top " . ( ($uniq > $topmax) ? $topmax : $uniq)  . " HIT\'ers **********$CRLF";
    #sumhash (\%iptab);
    #print OUT ($uniq >= $topmax) ? $topmax : $uniq;
    print OUT "Totally $sum and $uniq unique.$CRLF";
    printf(OUT "%4s %8s   %7s  %-15s  %-30s$CRLF", 'Rank', '%', 'Count', 'IP', 'FQDN');
    foreach $k (sort {$iptab{$b} <=> $iptab{$a}} keys %iptab )
    {
	@_ = split "¤", $k;
	printf(OUT "%4d (%6.2f%%)  %7d  %-15s  %-30s$CRLF", $xx, ($iptab{$k}*100/$sum), $iptab{$k},$_[0], resolve($_[0]));
	if ($xx++ == $topmax) { last; }
    }
    
    
    # List attempts to access non-existing pages
    print OUT "$CRLF$CRLF********** Access attempts generating 403/404 messages **********$CRLF";
    
    sumhash (\%s01);
    if ($uniq gt 0) {
	print OUT "Totally $sum and $uniq unique.$CRLF";
	printf(OUT "%7s  %7s  %-15s$CRLF",  'Count', 'Status', 'URL');
	foreach $k (sort {$s01{$b} <=> $s01{$a}} keys %s01 )
	{
	    @_ = split "¤", $k;
	    printf(OUT "%7d  %7d  %-15s$CRLF",  $s01{$k},$_[0], $_[1]);
	}
	
	print OUT "$CRLF$CRLF********** Top $topmax IP\'s generating 403/404 **********$CRLF";
	$xx = 1;
	sumhash (\%s02);
	print OUT "Totally $sum and $uniq unique.$CRLF";
	print OUT "The top IP's on this list could be the source for vulnerability scans of your  site.$CRLF";
	printf(OUT "%4s %7s   %-15s  %s$CRLF",  'Rank', "Count", "IP-Address", "FQDN");
	foreach $k (sort {$s02{$b} <=> $s02{$a}} keys %s02 )
	{
	    @_ = split "¤", $k;
	    #printf(OUT "Count:  %7d  IP: %-15s (%s)$CRLF",  $s02{$k},$_[0], $sip{$_[0]})
	    printf(OUT "%4d %7d   %-15s  %s$CRLF",  $xx, $s02{$k},$_[0], $sip{$_[0]});
	    if ($xx++ == $topmax) { last; }
	}
	
	print OUT "$CRLF$CRLF********** Top $topmax Files per IP genererating 403/404 **********$CRLF";
	$xx = 1;
	sumhash (\%s0);
	print OUT "Totally $sum and $uniq unique.$CRLF";
	print OUT "This could inidicate either faultly links on your site, or$CRLF";
	print OUT "a perpetrator looking for vulnerabilities.$CRLF";
	printf(OUT "%4s %7s  %-15s  %s$CRLF", 'Rank', 'Count', 'Src IP', 'URL' );
	foreach $k (sort {$s0{$b} <=> $s0{$a}} keys %s0 )
	{
	    @_ = split "¤", $k;
	    printf(OUT "%4d %7d  %-15s  %s$CRLF",  $xx, $s0{$k},$_[0], $_[1]);
	    if ($xx++ == $topmax) { last; }
	}
    } else {
        printf OUT "None. $CRLF";
    }
    
	
    
    # 5xx Status
    print OUT "$CRLF********** Top $topmax IP\'s causing Server Errors (5xx) ********** $CRLF";
    sumhash (\%s42);
    if ($uniq > 0) {
	$xx = 1;
	print OUT "Totally $sum and $uniq unique.$CRLF";
	print OUT "This could indicate various attempts to cause your web server$CRLF";
	print OUT "to produce erronous results.$CRLF";  
	printf OUT "%7s  %-7s  %-15s %s$CRLF",  'Count', 'Status', 'Src IP', 'FQDN';
	foreach $k (sort {$s42{$b} <=> $s42{$a}} keys %s42 )
	{
	    @_ = split "¤", $k;
	    printf(OUT "%7d  %-7d  %-15s %s$CRLF",  $s42{$k},$_[0], $_[1], $sip{$_[1]});
	    if ($xx++ == $topmax) { last; }
	}
   
    
	# 5xx Status
	print OUT "$CRLF********** Top $topmax URL\'s causing Server Errors (5xx) ********** $CRLF";
	$xx = 1;
	sumhash (\%s4);
	print OUT "Totally $sum and $uniq unique.$CRLF";
	printf OUT "%7s  %-7s  %-20s$CRLF",  'Count', 'Status', 'URL';
	foreach $k (sort {$s4{$b} <=> $s4{$a}} keys %s4 )
	{
	    @_ = split "¤", $k;
	    printf(OUT "%7d  %-7d  %-20s$CRLF",  $s4{$k},$_[0], $_[1]);
	    if ($xx++ == $topmax) { last; }
	}
	
	print OUT "$CRLF********** Top $topmax URL\'s & IP\'s causing Server Errors (5xx) ********** $CRLF";
	$xx = 1;
	sumhash (\%s41);
	print OUT "Totally $sum and $uniq unique.$CRLF";
	printf OUT "%7s  %-7s  %-15s  %s$CRLF", 'Count', 'Status', 'Src IP', 'URL' ;
	foreach $k (sort {$s41{$b} <=> $s41{$a}} keys %s41 )
	{
	    @_ = split "¤", $k;
	    printf(OUT "%7d  %-7d  %-15s  %s$CRLF",  $s41{$k},$_[0], $_[2], $_[1]);
	    if ($xx++ == $topmax) { last; }
	}
    } else {
        printf OUT "None. $CRLF";
    }
 
    # Top Referers
    $xx = 1;
    print OUT "$CRLF********** Top $topmax Referers ********** $CRLF";
    sumhash (\%s11);
    if ($uniq > 0 ) {
	print OUT "Totally $sum and $uniq unique.$CRLF";
	printf OUT "%7s  %-50s$CRLF", 'Count', 'Referer' ;
	foreach $k (sort {$s11{$b} <=> $s11{$a}} keys %s11 )
	{
	    @_ = split "¤", $k;
	    printf(OUT "%7d  %-50s $CRLF",  $s11{$k},$_[0]);
	    if ($xx++ == $topmax) { last; }
	}
    } else {
	printf OUT "Not Available$CRLF";
    }
    
    # Top Browsers
    $xx = 1;
    print OUT "$CRLF********** Top $topmax Browsers ********** $CRLF";      
    sumhash (\%s12);
    if ($uniq > 0 ) {
	print OUT "Totally $sum and $uniq unique.$CRLF";
	printf OUT "%7s  %-50s$CRLF", 'Count', 'Browser' ;
	foreach $k (sort {$s12{$b} <=> $s12{$a}} keys %s12 )
	{
	    @_ = split "¤", $k;
	    printf(OUT "%7d  %-50s $CRLF",  $s12{$k},$_[0]);             
	    if ($xx++ == $topmax) { last; }
	}
    } else {
	printf OUT "Not Available$CRLF";
    }

    # Check for Cookie Manipulation
    $xx = 1;
    print OUT "$CRLF********** Same Cookie from different IP-addresses ********** $CRLF";
    sumhash (\%s14);
    if ($uniq gt 0) {
	print OUT "Totally $sum and $uniq unique. Showing at maximum the top $topmax.$CRLF";
	print OUT "This could inidicate attempted session hijacking,$CRLF";
	print OUT "or users coming via a non-ip session aware proxy.$CRLF";
	printf OUT "%9s %-15s %s$CRLF", 'Count', 'IP', 'FQDN';
	#foreach $k (sort {$s14{$b} <=> $s14{$a}} keys %s14)
	$old = '';
	foreach $k (sort keys %s14)
	{
	    #print "\$k: $k\n";
	    @_ = split "¤", $k;
	    #print "\$_\[0\]:$_[0]$CRLF";
	    if ($old ne $_[0]) {
		print OUT "$CRLF";
		#$co = $cookie;
		$co = (length($_[0]) > 60) ? substr($_[0],0,20) . ".. [ Truncated ] .." . substr($_[0], length($$_[0])-20,20) : $_[0];
		    
		printf OUT "Cookie: %s$CRLF", $co;
	    }
	    printf OUT "%9d %-15s %s$CRLF", $s14{$k}, $_[1], resolve($_[1]);
	    
	    $old = $_[0];
	    #if ($xx++ == $topmax) { last; }
	}
    } else {
	print OUT "None found.$CRLF";
    }

    # Check for Directory scanning / Listing
    $xx = 1;
    print OUT "$CRLF********** Unsuccessful Subdirectory Listing Attempts ********** $CRLF";
    sumhash (\%s15);
    if ($uniq gt 0) {
        print OUT "Totally $sum and $uniq unique.$CRLF";
        #print OUT "This could inidicate attempted session hijacking.$CRLF";
        printf OUT "%7s %7s %-40s %-15s %-4s$CRLF", 'Count', 'Status', 'URL', 'IP', 'FQDN';
        foreach $k (sort {$s15{$b} <=> $s15{$a}} keys %s15)
        {
            @_ = split "¤", $k;
            printf(OUT "%7d %7s %-40s %-15s %s$CRLF",  $s15{$k},$_[2], $_[1], $_[0], resolve($_[0]));
            if ($xx++ == $topmax) { last; }
        }
    } else {
        print OUT "None found.$CRLF";
    }

    # List attempted form manipulation
    $xx = 1;
    print OUT "$CRLF********** Suspected Form Data Manipulation ********** $CRLF";
    sumhash (\%s16);
    if ($uniq gt 0) {
        print OUT "Totally $sum and $uniq unique.$CRLF";
        print OUT "This could inidicate attempted unauthorized database access.$CRLF";
        printf OUT "%7s %-30s %-15s %-15s %-20s$CRLF", 'Count', 'Query', 'IP', 'FQDN' ;
        foreach $k (sort {$s16{$b} <=> $s16{$a}} keys %s16)
        {
            @_ = split "¤", $k;
            printf(OUT "%7d %-30s %-15s %-15s$CRLF",  $s16{$k}, $_[1], $_[0], resolve($_[0]));
            if ($xx++ == $topmax) { last; }
        }
    } else {
        print OUT "None found.$CRLF";
    }

    # List attempted Anonymous Proxy Scans
    $xx = 1;
    print OUT "$CRLF********** Attempts to locate Proxy ********** $CRLF";
    sumhash (\%s17);
    if ($uniq gt 0) {
        print OUT "Totally $sum and $uniq unique.$CRLF";
        print OUT "Successfull attempts could indicate that your web server can$CRLF";
	print OUT "be used for staging Internet Attacks and fraud.$CRLF";
        printf OUT "%7s %6s %-40s %-15s %-15s %s$CRLF", 'Count', 'Status', 'URL', 'IP', 'FQDN';
        foreach $k (sort {$s17{$b} <=> $s17{$a}} keys %s17)
        {
            @_ = split "¤", $k;
            printf(OUT "%7d %6d %-40s %-15s %s$CRLF",  $s17{$k}, $_[1], $_[2], $_[0], resolve($_[0]));
            if ($xx++ == $topmax) { last; }
        }
    } else {
        print OUT "None found.$CRLF";
    }

    # List exceedingly Long URL's
    $xx = 1;
    print OUT "$CRLF********** Exceedingly Long URL's ********** $CRLF";
    sumhash (\%s18);
    if ($uniq gt 0) {
        print OUT "Totally $sum and $uniq unique.$CRLF";
        print OUT "These could indicate attempts to locate and use Buffer Overflows$CRLF";
        print OUT "to compromise the Web Server, and shoud be considererd as serious attempts to breach Security.$CRLF";
        printf OUT "%7s %6s %10s  %-15s %-30s %-15s$CRLF", 'Count', 'Status', 'Length', 'URL', 'FQDN' ;
        foreach $k (sort {$s18{$b} <=> $s18{$a}} keys %s18)
        {
            @_ = split "¤", $k;
            printf(OUT "%7d %6s %10s  %-30s\n%26s %-15s %s $CRLF",  $s18{$k}, $_[3], $_[2], $_[0] ,'', $_[1], resolve($_[1]));
	    if ($xx++ == $topmax) { last; }
	}
    } else {
	print OUT "None found.$CRLF";
    }
    
    close OUT;
}




# Routine to print Statistics for later analysis
sub printstats {
    print STATS '<?xml version="1.0"?>' . "\n";
    print STATS '<SecSrchRun run="secsrch.pl" version="' . $VERSION . '" xmloutputversion="1.0">' . "\n";
    print STATS "<PeriodStart>$mindate</PeriodStart>\n";
    print STATS "<PeriodEnd>$maxdate</PeriodEnd>\n";
    print STATS "<host>\n";
    print STATS "<hostname>" . $cname . "</hostname>\n";
    print STATS "<numlines>" . $numlines . "</numlines>\n";
    print STATS "<errorlines>" . $logformat{'Unknown'} . "</errorlines>\n";

    print STATS "<httpstats>\n";
    print STATS "<code200>"  ;

    print STATS "</host>\n";
    print STATS "</SecSrchRun>\n";

}


######################
# Below are various routines to ease things up

sub prntx () {
    my ($xmlname, $xmlvalue) = @_ ;
    print OUT "<$xmlname>" . $xmlvalue . "<\/$xmlname>\n";
    
    
}

sub sumhash  ()
{
    # Get Total, unique, Max and Min from hash
    $sum = 0; $uniq = 0; 
    undef $max;
    foreach $href (@_)
    {
	while ( ($key, $value) = each %$href ) 
	{
	    $sum = $sum + $value; 
	    $uniq++ ; 
	    if (defined $max) { if ($max < $value ) { $max = $value; }
	    } else { $max = $value; }
	    if (defined $min) { if ($min > $value ) { $min = $value; }         
	    } else { $min = $value; }

	}
    }
}

# Routine 'borrowed' from snort_stat...

sub resolve {
    
    local ($mname, $miaddr, $mhost = shift);
    if (($opt_N eq 1) || ($res eq 'false')) {return ''}
    #if ($opt_N eq 1) {return ''}
    # if (not $res eq 'true') { return $mhost }
    $miaddr = inet_aton($mhost);
    $HOSTS{$mhost} = gethostbyaddr($miaddr, AF_INET);
    if (!$HOSTS{$mhost}) {
	$mname ="";
	#die if $@ && $@ ne "alarm\n";  # propagate errors
	if ($mname =~ /^$/) {
	    $mname = $mhost;
	}
	$HOSTS{$mhost} = $mname;
    }
    return $HOSTS{$mhost};
}

sub slog {
    setlogsock('unix');
    openlog('SecSrch.pl', 'cons,pid', 'local2');
    syslog('info', @_);
    closelog;
}

sub plog {
    # Generate Debug Log
    open DBG, ">>/tmp/secsrch.dbg";
    print DBG @_;
    close DBG;
}

sub trunc {
    # Function to truncate values?
    local ($f, $l = shift);
    $fl = length($f);
    if ($fl > $l) {
	$d = $fl - $l; 
	$x = substr($f, 0, (($fl/2) - ($d / 2)));
    }

    return $x;

}

sub urlencode () {
    $x = shift;
    $x =~ s/\&/\&amp;/g;
    return $x;
}

sub save_chart {
    my $chart = shift or die "Need a chart!";
    my $name = shift or die "Need a name!";
    local(*OUT);

    my $ext = $chart->export_format;

      open(OUT, ">$name.$ext") or 
	  die "Cannot open $name.$ext for write: $!";
    binmode OUT;
    print OUT $chart->gd->$ext();
    close OUT;
}


# And that's about all there is....
