#!/usr/bin/perl
# $Header: /home/mibl/Dev/slac/RCS/secsrch.pl,v 1.93 2008/02/20 08:00:13 mibl Exp $
$REVISION = '$Revision: 1.93 $';

# (C) Mike Blomgren 2001-02-21
# mibl@a51.mine.nu
# 
# A Perl script to parse Webserver logfiles, and search for
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
# You are free to use the script for personal use. 
# 
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
# 2002-05-22 2.27 Started rework for 'logger' function
# 2002-06-10 2.28 Added syslog logging of progress
#                 Added Cookie hijacking detection
# 2002-06-16 2.29 Added detection of URI Query manipulation attempts
# 2002-08-03 2.30 Various improvements
# 2003-03-18 2.31 Started working on long-time statistics gathering
# 2003-03-22 2.32 Also added XML output, but this is not finished in any way.
# 2003-04-03 2.33 Gave up on XML. This is really crossing the river for water.
# 2003-06-02 2.35 Added XML again... Maybe I can find it usefull after all...
# 2003-06-29 2.37 Added detection of  XSS scripting attmpts
# 2003-10-19 2.39 Added possibility to only dissplay entries in report where we
#                 actually found something - to make it shorter and 
#                 more relevant.
# 2004-12-04 2.40 Started adding support for GD::Graphing output
#                 Adding support for fortigate wlog.files for web usage stats.
# 2007-08-27 2.41 Started Adding support for FortiGate Log Files

# 
# To Do...:
# Add 'Bursty surfing detection' 
# Add 'Crawler detection'
# Improve parsing performance. 2000-4000 lines/second is not impressive...
#   and the parsing is what sucks all performance.
# Add XML modularized output for easy ASCII/HTML/whatever output
# Add Analysis based on time - WHEN do 5xx errors occur, etc? Related to a single time, or spread out during the day
# Add maximum hits per a single second (to locate possile resource starvation attempts)
# Look for any delays in traffic (log times without any hits) - To locate succesful DoS, or just 'down-times'
# Do Whois-lookup on IP-addresses in printed in report. (Whith GeekProxy maybe?)
# Add Automatic detection and split of logfiles which contain data from several webservers
# When listing logged in users, check at which times they are logged in.

$VERSION = '2.39';
   
$res = 'true';  # Set to true if we should attempt to resolve IP's to FQDN
#$res = 'false';

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

use XML::Writer;
#use IO;

slog('Starting Exec');

getopts('i:o:PmWhvNpsXOC:M:I:L');  
# i <infile> - input files
# o <outputfile> - output file
# P - Generate detailed Debug Log (not implemented very well)
# m - Minimal output - only print headers where we have something to report
# W - being run as a CGI (Use <br>\n as $CRLF)
# h - only print help
# v - print version and exit
# N - don't do name lookups
# p - Print a descriptive text for each report section
# s - Only print stats (Not completely implemented)
# X - Use XML output for report
# O - Overwrite output file if it exists
# C <config> - CustomLog Configuration
# M # - Number of lines to read before exiting (used mostly for testing the app)
# I <uploadid> - Print progress for interactive download, to temp file
# L - Learn mode - print first line to see if we can parse it correctly


slog("CustomLog Opts: $opt_C");

if ($opt_W ne '') {
    $CRLF = "\<br\>\n";
}

# Print descriptions?
if ($opt_p ne '') { $pdesc = 1; } else { $pdesc = 0 }

if (defined $opt_I) {
    $uploadid = $opt_I;
    $statfile = "/var/tmp/$uploadid.log";
}

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

$URL_MAX = 400;       # Max length of URLs to warn of if exceeding this length
$SITE = 'http://a51.mine.nu/';
$SITE_DIR = '';

$mindate = '';
$maxdate = '';

$starttime = time;
$starttimetext = localtime;

if (defined $opt_i) {
    $infile = $opt_i;
} else {
    $infile = $ARGV[0];
}
#print STDERR "got $infile\n";
if (sanitize($infile) ne 0) { die "Invalid characters found in filename. The error is logged.\n";}
#print STDERR "got infile\n";
if (defined $opt_o) {
    $outfile = $opt_o;
} else {   
    $outfile = $ARGV[1];
}
if (sanitize($outfile) ne 0) { die "Invalid charcaters found in filename. The errror is logged.\n"; }

$statsfile = '/tmp/stats.log';
$statsfile = '&STDOUT';
#print STDERR "got statsfile\n";
$topmax = 20;		# How many 'TOP HIT'ers' to display

# Check if we want help....
if ($opt_h eq 1) {
    print <<END_HELP;
SecSrch version $VERSION$CRLF
Analyses Web log files from a security perspective.$CRLF
Useage: [cat\|type] \<infile\> \| [perl] secsrch.pl \- [outfile]
or      [perl] secsrch.pl [options] -i <infile> [-o outfile]
or      [perl] secsrch.pl [options] -i \'<infile\*.gz>\' [-o outfile]
or      [perl] secsrch.pl [options] -i \'<infile\*.gz>\' [-o outdir]
Options:
 -i <input file(s)>. Must be quoted when using wildcards! I.e. 'ex*.log'
 -N Name resolution will not be performed.
 -  for <infile>, STDIN will be used for input.
 -  for <outfile>, STDOUT will be used for output.
 -s Only print summarized Statistics
 -X Print XML-output
 -o Overwrite any existsing outfile (default is not to overwrite).
 -C <Config String>  Use the supplied CustomLog directive to parse the logfile
 -W Run as cgi and terminate each line with <br\> instead if \\n.
 -p Print descriptive text for each report heading.
 -m Minimal output. Only print things we found to make report shorter.
 -h Print this help...
 -v Print version and exit.


END_HELP


    exit;
}

#Check for version info
if ($opt_v eq 1) {	
    print "$CRLFSecSrch by Mike Blomgren, v$VERSION$CRLF";	
    exit; 
}


# Which files do we open?....
#print STDERR "opening infiles\n";
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
	    $outfile = $outfile . '/SLAC.Multi.' . $1 . '.txt';
	} else {
	    if ($outfile eq '') {	
		$outfile = 'SLAC.Multi.' . $1 . '.txt';
	    }
	}	
    }
    else
    {	# If only one infile, use 'standard' output filename.
	if ($outfile eq '')
	{
	    $outfile = 'SLAC.' . $1 . '.txt';
	}
	if ( -d $outfile ) 
	{
	    $outfile = $outfile . '/SLAC.' . $1 . '.txt';
	}
	# Else $outfile = $outfile...
    }
    
}

slog("Infile: $infile");
slog("Outfile: $outfile");

if ((-f $outfile) && !($opt_O))
{
    print STDERR "File \'$outfile\' already exists. Exiting.$CRLF$CRLF";
    slog("File \'$outfile\' already exists. Exiting.");
    exit ;
}

open (OUT , ">$outfile") || die "Can't open $outfile for output\.";
#open (STATS, ">$statsfile") || die "Can't open $statsfile for output\.";
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
	    #print STDERR "$_";
	    # Can we parse the current line? 
	    if (splitline() != -1) {
		if (defined $opt_L) {
		    printheaders();
		    exit;
		}
		# Yepp, then make statistics...
		makestats();
		last unless ($maxreached ne 1);
	    }
	}
	die "Error reading from $file: $gzerrno$CRLF" if (($gzerrno != Z_STREAM_END) && ($maxreached ne 1));
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
		if (defined $opt_L) {
		    printheaders();
		    exit;
		}
		#if (m/getting/) {print "problems: $_"; exit;}
		if (($date le $mindate) || ($mindate eq '')) {$mindate = $date};
		if (($date gt $maxdate) || ($maxdate eq '')) {$maxdate = $date};
		# Yepp, then make statistics...
		makestats();
		last unless ($maxreached ne 1);
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

if (defined $opt_I) {
    pstatus($filename,0,"Analysis completed.");
}

slog('Exiting...');
exit 0;


sub splitline {
    $numlines++;
    if (($numlines % 10000) eq 0){
        slog("Completed: Pass $pass, $numlines lines.");
        if (defined $opt_P) {
            plog(localtime() . " Completed: Pass $pass, $numlines lines.\n");
	    print STDERR localtime() . " Completed: Pass $pass, $numlines lines.\n";
        }
	if (defined $opt_I) {
	    pstatus($filename, 0, "Analysis progress - Lines read: $numlines"); 
	    
	}
    }

    if ((defined $opt_M) && ($opt_M < $numlines)) {
        if (! defined $maxreached) {
            plog("Max lines ($opt_M) reached. Starting printout.\n");
            $maxreached = 1;
            return;
        }
        return;
    }


    #print "$timing\n";
    undef $serverip, $ip, $status, $date, $referer, $cookie, $uri, $url, $user, $httpver, $servername;
    if ($timing == 1) {
	my $t0 = new Benchmark;
	print "$t0\n";
    }
	
    # Split Logfile line into values.
    

    # Is the LogFormat specified as an input parameter?
    if (defined $opt_C ) {
	@header = split /\s+/,$opt_C;
	foreach $c (@header) { 
	    $p++; 
	    @HASH{$c}=$p;
	    #print "Hash: $HASH{$c}: $c\n";
	}
	foreach $x (keys %HASH) {
	    #print "$x $HASH{$x}\n";
	}
	$opt_C = lc($opt_C);
	
	#print "Match: $_\n";
	$format = $opt_C;
	$format =~ s/%h/([\\d\\.]+)\\s?\n/g;  # $ip
	$format =~ s/%l/([\\w\\d\\-\\.]+)\\s?\n/g; # Remote logname (unused)
	$format =~ s/%u/([\\w\\d\\-\\.]+)\\s?\n/g;  # Logged in user
	$format =~ s/%t/(\\[\.+\\])\\s?\n/g;
	$format =~ s/\\"%r\\"/(\\"\.+?\\")\\s?\n/g;
	$format =~ s/%\>s/(\\d+)\\s?\n/g;
	$format =~ s/%b/(\.+)\\s?\n/g;
	$format =~ s/\\"\%\{user-agent\}i\\"/\\"(\.+?)\\"\\s\n/gi;
	#print "\$format: $format\n";
	
	$match = $_ =~ m/$format/x;
	#print "Matches: $match\n";
	if ($match lt 1) {
	    slog("Error. Custom Log Optoins doesnt match Log File");
	    print "$_\n";
	    print "Format: $format\n";
	    die "Custom Log Options dont match log file";

	}

	#print "\$1: $1\n\$2: $2\n\$3: $3\n\$4: $4\n\$5: $5\n\$6: $6\n\$7: $7\n\$8: $8\n";
	$F{'1'} = $1;	$F{'2'} = $2;	$F{'3'} = $3; 	$F{'4'} = $4;
	$F{'5'} = $5;	$F{'6'} = $6;	$F{'7'} = $7;	$F{'8'} = $8;
	$F{'9'} = $9;	$F{'10'} = $10;	$F{'11'} = $11;	$F{'12'} = $12;
	$F{'13'} = $13;
	$user = $F{$HASH{'%u'}};
	$ip = $F{$HASH{'%h'}};
	$serverip = $F{$HASH{'%A'}};
	$date = $F{$HASH{'%t'}};
	if ($date =~ m/\[(\d+)\/(\w+)\/(\d+)\:([\d\:]+)/g) {
	    $date = "$3-$MONS{$2}-$1 $4";
	}
		       #[05/Sep/2004:00:00:01 +0200] 
	$status = $F{$HASH{'%>s'}};
	$len = $F{$HASH{'%b'}};
	$browser = $F{$HASH{'\"%{user-agent}i\"'}};
	
	$url = $F{$HASH{'\"%r\"'}};
	$url =~ m/\"([\w]+)\s(.+)\s(.+)\"/g;
	$method = $1;
	$url = $2;
	$httpver = $3;
	if (defined $opt_L) {
	    printheaders();
	    exit;
	}
	#print $user, $ip;
	
    }
	
    
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
	$user = $HASH{'cs-username'} unless not defined $HASH{'cs-username'};
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
	$httpver = $HASH{'cs-version'} unless not defined $HASH{'cs-version'}; 
	#print STDERR $httpver;
	$status = $HASH{'sc-status'};
	$referer = $HASH{'cs(Referer)'} unless not defined $HASH{'cs(Referer)'};
	$cookie = $HASH{'cs(Cookie)'} unless not defined $HASH{'cs(Cookie)'};
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
	if ( m/^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})   # IP Address
	     \s([\w\d\-]+?)                        # User
	     \s([\-]+?)                        # unused
	     \s(\[.+\])                     # Date
	     \s\"(.+?)\"                    # Url
	     # Match regardless of HTTP Version.
	     \s(\d+?)                       # Statuscodes
	     \s([\-\d]+?)                   # Size
	     \s(?:\"(.*?)\")?                    # Optional Referer
	     (?:\s\"(.*?)\")?                    # Optional Browser type
	     (?:\s\"(.*?)\")?               # Optional Cookie
	     /iox )                    
	{
	    
	    $logformat{'Common Log Format'}++;
	    $ip = $1; $na1 = $2; $user=$3; $date = $4;
	    $url = $5; 
	    $status = $6; $len = $7;
	    #print "DBG: $url\n";
	    #$query = $6;
	    #$httpver = $7;
	    $referer = $8; $browser = $9; $cookie = $10;
	    $uri = $url . '?' . $query;
	    #print "$httpver\n";
	    if ($url =~ m/([\w\d]+)\s(.*)\s(.*)/iox) {
		$method = $1;
		$url = $2;
		$httpver = $3;
		#print "M: $method\nU:$url\n";
	    }
	    if ($url =~ m/(.*)\?(.*)/) {
		$query = $2;
		#print "Q: $query";
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

	elsif ( m/^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})   # Client IP 
	    \s(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})     #Srv IP
	    \s([\-]+?)                        # Unused
            \s(.+?)                        # User
            \s(\[.+\])                     # Date
            \s\"(.*)\"               # Url
	    # (?:(\?.*\s))?
            # (?:(.*?)\")?                 # Match regardless of HTTP Version.
            \s([\d\-]+?)                       # Statuscodes
            \s([\-\d]+?)                   # Size
	    \s(.*?)                         # Unused...
            \s\"(.*?)\"                    # Optional Referer
            \s\"(.*?)\"                    # Optinal Browser type
            \s\"(.*?)\"               # Optional Cookie
            /iox )
        {
	    $logformat{'Apache Custom Combined'}++;
	    $ip = $1;
	    $serverip = $2;
	    $user = $4;
	    $date = $5; 
            $url = $6; $status = $7; $len = $8; $referer = $10;
	    $browser = $11; $cookie = $12;
	    #print "$cookie\n";
            #print "$6";
            if ($url =~ m/([\w\d]+)\s(.*)\s(.*)/iox) {
                $method = $1;
                $url = $2;
                $httpver = $3;
                #print "M: $method\nU:$url\n";
            }
            if ($url =~ m/(.*)\?(.*)/) {
                $query = $2;
                #print "Q: $query";
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

	elsif ( m/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})   # Client IP 
	    \s(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})     #Srv IP
	    \s([\w\d\.]+)    # Sitename
	    \s([\-]+?)                        # Unused
            \s(.+?)                        # User
            \s(\[.+\])                     # Date
            \s\"(.*)\"               # Url
	    # (?:(\?.*\s))?
            # (?:(.*?)\")?                 # Match regardless of HTTP Version.
            \s([\d\-]+?)                       # Statuscodes
            \s([\-\d]+?)                   # Size
	    \s(.*?)                         # Unused...
            \s\"(.*?)\"                    # Optional Referer
            \s\"(.*?)\"                    # Optinal Browser type
            \s\"(.*?)\"               # Optional Cookie
            /iox )
        {
	    $logformat{'Apache Custom Mikes Combined'}++;
	    $ip = $1;
	    $serverip = $2;
	    $sitename = $3;
	    $user = $5;
	    $date = $6; 
            $url = $7; $status = $8; $len = $9; $referer = $11;
	    $browser = $12; $cookie = $13;
	    #print "$cookie\n";
            #print "$6";
            if ($url =~ m/([\w\d]+)\s(.*)\s(.*)/iox) {
                $method = $1;
                $url = $2;
                $httpver = $3;
                #print "M: $method\nU:$url\n";
            }
            if ($url =~ m/(.*)\?(.*)/) {
                $query = $2;
                #print "Q: $query";
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

	elsif ( m/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})   # Client IP
		\s(.+?)         # Virtual Server
            \s(.+?)                        # Unused
            \s(\[.+\])                     # Date
            \s\"(.*)\"               # Url
            \s([\d\-]+?)                       # Statuscodes
            \s([\-\d]+?)                   # Size
            \s\"(.*?)\"                    # Optional Referer
            \s\"(.*?)\"                    # Optinal Browser type
            /iox )
        {
            $logformat{'Domino Extended'}++;
            $ip = $1;
            $serverip = $2;
            $user = $3;
            $date = $4;
            $url = $5; $status = $6; $len = $7; $referer = $8;
            $browser = $9; #$cookie = $12;
            #print "$cookie\n";
            #print "$6";
            if ($url =~ m/([\w\d]+)\s(.*?)\s(.*)/iox) {
                $method = $1;
                $url = $2;
                $httpver = $3;
                #print "M: $method\nU:$url\n";
            }
            if ($url =~ m/(.*)\?(.*)/) {
                $query = $2;
                #print "Q: $query";
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


	} 
	elsif ( m/([\d\n\w\-\.]+)   # Client hostname
            \s([\-]+?)                        # Unused
            \s([\-]+?)                        # Unused
            #\s(.+?)                        # User
            \s(\[.+\])                     # Date
            \s\"(.*)\"               # Url
            # (?:(\?.*\s))?
            (?:(.*?)\")?                 # Match regardless of HTTP Version.
            \s([\d\-]+?)                       # Statuscodes
            \s([\-\d]+?)                   # Size
            #\s(.*?)                         # Unused...
            \s\"(.*?)\"                    # Optional Referer
            \s\"(.*?)\"                    # Optional Browser type
            #\s\"(.*?)\"               # Optional Cookie
            /iox )
        {
            $logformat{'Apache Custom Combined 2'}++;
	    $ip = $1;
	    #$serverip = $2;
	    #$sitename = $3;
	    #$user = $5;
	    $date = $4; 
            $url = $5; $status = $7; $len = $9; $referer = $9;
	    $browser = $10; $cookie = $13;
	    #print "$cookie\n";
            #print "$6";
            if ($url =~ m/([\w\d]+)\s(.*)\s(.*)/iox) {
                $method = $1;
                $url = $2;
                $httpver = $3;
                #print "M: $method\nU:$url\n";
            }
            if ($url =~ m/(.*)\?(.*)/) {
                $query = $2;
                #print "Q: $query";
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
	
	# No Match...

	else 
	{
	    print "Unable to parse logline: $_\n";
	    $logformat{'Unknown'}++;
	    $badlines++;
	}
    }
    #if ($timing == 1) {
#	my $t1 = new Benchmark;
#	print "Splitline: ".timestr(timediff($t1,$t0));
#	
#    }
	    
}

sub makestats {
    # Start collecting stats on the parsed logfile entries

    # Check for Exceedingly Long URL's before doing more statistics
    if ((length $url) > $URL_MAX ) {
	$lenu = length($url);
        $url = substr($url, 0, 15) . ' [ Truncated ] ' . substr($url, length($url)-15,15);
        $s18{"$url�$ip�$lenu�$status"}++;
    }
    
    
    # Look for 'File not found' or 'Forbidden' messages, but filter 
    # out the obvious 404 generators...
    if (($status =~ m/404|403|406|400/))
	#&& (not $url =~ m/favicon|GET.\/images|\/img\/meny/ix))
    {
	$s0{"$ip�$url"}++;
	$s01{"$status�$url"}++;
	$s02{"$ip"}++;
	# Why do we resolve the ip-address here??? /Mike
	if ($sip{$ip} eq undef) {	
	    $sip{$ip} = resolve($ip);
	}
    }
    
    # Logged In Users
    if (defined $user) {
	#print "$user\n";
	if (($user ne '-') and ($user ne 'N/A'))
	{
	    $s1{"$user�$ip"}++;
	    # Why do we resolve the ip-address here??? /Mike
	    if ($sip{$ip} eq undef) {	$sip{$ip} = resolve($ip) };
	}
	$s10{"$user"}++;
	#print "$user: $s10{$user}\n";
    } else {
	$userundef++;
    }
    
    # Unauthorized messages
    if ($status eq '401')
    {
	$s2{"$status�$ip�$url�$user"}++;
    }
    
    # Look for 'dangerous' files successfully downloaded to the client
    # This needs to be modified depending on what system you'r running (unix/VMS/Windows/whatever)
    if ($status eq '200') {
	if ($url =~ m/passwd|\/etc\/shadow|nc.exe|cmd1\.exe|ncx\.exe|inetd|\/services|access\.log|cmd\.exe|\.\%..\%..|\.url|\.bat/ix) {
	    $s3{"$ip�$url"}++;
	}
    }
    
    # Show URL's which have generated a 5xx error
    if ($status =~ m/^5/)
    {
	$s4{"$status�$url"}++;
	$s41{"$status�$url�$ip"}++;
	$s42{"$status�$ip"}++;
	if ($sip{$ip} eq undef) { $sip{$ip} = resolve($ip) };
	$s43{"$date�$ip"}++;
	#print "$date $ip\n";
    }

    # Look for URL's containing non printable characters
    if ($url =~ m/[\x00-\x1f]|[\x7f-\xff]/) 
    {
	#print "$url\n";
	$s45{"$ip\#\#$url"}++;
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
	#print STDERR "H:$httpver  Q:$query\n";
    } else {
	$httpverundef++;
    }
    
    # List requests with illegal or missing http version fields. 
    #if ((not $httpver =~ m/^HTTP\/\d\.\d$|N\/A/i) && (defined $httpver))
    if ((not $httpver =~ m/^HTTP\/1.0$|^HTTP\/1.1$|N\/A/i) && (defined $httpver))
    {
	$s61{"$httpver�$ip"}++;
    }
    
    # Get Hits per hour
    $s7{$hr}++;
    if ($s7{$hr} > $hrmax) {$hrmax = $s7{$hr}}

    # Look at Referers
    if (defined $referer) {
	unless ($referer =~ m/^\s*$/) { $s11{$referer}++;};
	if ($referer eq '-') {
	    $s131{"$ip�$url"}++;
	}
    } else {
	$refererundef++;
    }

    # Count Browser versions
    unless ($browser =~ m/^\s*$/) {$s12{$browser}++;}

    # Check for Cookie Manipulation  - i.e. same cookie from different IP's
    if (defined $cookie) {
	if (($cookie ne '-') && ($cookie ne '')) {
	    #print "Cookie: $cookie   - IP: $ip\n";
	    if (defined $s13{$cookie}) {
		if (($s13{$cookie} ne $ip) && (! defined $s14{"$cookie�$ip"})){
		    #print "Cookie: $cookie \n Old IP: $s13{$cookie} New IP: $ip\n";
		    #Then we have problems...
		    
		    #$s14{"$cookie"}++;
		    $s14{"$cookie�$ip"}++;
		    $s14{"$cookie�$s13{$cookie}"}++;
		} 
		
	    } else {
		#    #print "CIP: $ip\n";
		$s13{$cookie} = $ip;
		#$s14{"$cookie�$ip"}++;
		#$s14{"$cookie�$ip"}++;
		#print "CIP: $cookie = $ip\n";    
		#}
	    }
	}
    } else {
	$cookieundef++;
    }
    
    # Check for unsuccessfull attempts to List directories
    #print "$url\n";
    if (($url =~ m/\/$/) && ($status ne '200') && ($status ne '304') && ($status ne '302')) {
	#print "URL $url $status\n";
	$s15{"$ip�$url�$status"}++;
	$s151{"$ip"}++;
    }
    
    # Check for attempts to manipulate form data. 
    # For example 'SELECT' in the Query, or other 'abnormal' characters
    if ($query =~ m/select|\'|\"|\;|javascript|\>|\</gi) {
	$s16{"$ip�$query"}++;
    }

    # Check for Anonymous Proxy Scanning, i.e. URL starts with 'HTTP...' or  
    # uses CONNECT method
    #if ($_ =~ m/connect/i ) {print $url};
    if (($url =~ m/^[\w]+?\s+HTTP[s]*\:/i) || ($method =~ m/^connect/i)) {
	#print $url;
	$s17{"$ip�$status�$method $url"}++;
    }

    # List HTTP Methods found
    if ($method ne '') {
	$s19{$method}++;
    }

    # Check if Several Servers listed
    if (! defined $serverip) { $serverip = '<No Name>' };
    $s20{"$serverip $sitename"}++;

    # Chech if url contains <SCRIPT > tag for XSS attempts
    if ($url =~ m/\<script/ig) {
	$s21{"$ip�$url"}++;
    }

    #print "stats done\n";
}


sub printall {

    # Check if results are OK, before mailing report
    if ($numlines eq $logformat{'Unknown'}) {
	exit 99;
    }
    slog('Printing text output');
    if ($opt_W) {print OUT "<table border=\"1\"><tr><td colspan=\"2\">\n";}
    print OUT "Security Log File Analysis$CRLF";
    if ($opt_W) {print OUT "</td></tr><tr><td colspan=\"2\">\n";}
    print OUT "SLAC v $VERSION $REVISION  $SITE$SITE_DIR $CRLF$CRLF";
    if ($opt_W) {print OUT "</td></tr><tr><td>\n";}
    print OUT "Inputfile(s): ";
    if ($opt_W) {print OUT "</td><td>\n";}
    print OUT  join (" ",@list). "$CRLF";
    if ($opt_W) {print OUT "</td></tr><tr><td>\n";}
    #print OUT "Outputfile: $outfile $CRLF";
    print OUT "Log Start: ";
    if ($opt_W) {print OUT "</td><td>\n";}
    print OUT "$mindate$CRLF";
    if ($opt_W) {print OUT "</td></tr><tr><td>\n";}
    print OUT "Log Stopp: ";
    if ($opt_W) {print OUT "</td><td>\n";}
    print OUT "$maxdate$CRLF";
    if ($opt_W) {print OUT "</td></tr><tr><td>\n";}
    #print OUT "Execution started: " . $starttimetext . "$CRLF";
    #print OUT "Execution stopped: " . localtime() . "$CRLF";
    printf OUT "nr of analyzed rows: ";
    if ($opt_W) {print OUT "</td><td>\n";}
    printf OUT "%7d $CRLF", $numlines;
    if ($opt_W) {print OUT "</td></tr><tr><td>\n";}
    #printf OUT "nr of non-analyzed rows:    %7d $CRLF", $logformat{'UNKNOWN'};

    printf OUT "nr of unique IP-addresses: ";
    if ($opt_W) {print OUT "</td><td>\n";}
    printf OUT "%7d $CRLF", $numip;
    if ($opt_W) {print OUT "</td></tr><tr><td colspan=\"2\">\n";}
    print OUT "Rows identified as:$CRLF";
    if ($opt_W) {print OUT "</td></tr><tr><td>\n";}
    foreach $x (keys %logformat) {
	if ($opt_W) {print OUT "<div>\n";}
	printf OUT " %-24s %9d$CRLF", $x, $logformat{$x};
	if ($opt_W) {print OUT "</div>\n";}
    }
    if ($opt_W) {print OUT "</td></tr><tr><td>\n";}
    slog("Nr of Analyzed rows: $numlines");
    if ($opt_W) {print OUT "</td></tr><tr><td>\n";}
    slog("Rows/sec: " . $numlines / (time - $starttime + 1));
    if ($opt_W) {print OUT "</td></tr><tr><td>\n";}
    #printf OUT "nr of analyzed rows/second: %7d $CRLF", $numlines / (time - $starttime + 1);
    #printf OUT "nr of $logformat{'CLF'}\n";
    if ($opt_W) {print OUT "</td></tr><tr><td>\n";}
    if ($opt_N ne '') 
    {  print OUT "Name Resolution has NOT been performed.$CRLF$CRLF"; }
    #else
    #{  print OUT "Name Resolution has been performed.$CRLF$CRLF"; }

    sumhash (\%s20);
    if ($sum gt 0) {
	print OUT "Servers analyzed ($uniq):                Rows$CRLF";
	foreach $x (sort keys %s20 ) {
	    printf OUT "  %-30s %9d$CRLF", $x, $s20{$x};
	}
    }
    if ($opt_W) {print OUT "</td></tr><tr></tr>\n";}
    if ($opt_W) {print OUT "</table>\n";}

    
    # Show number of hits/hour
    print OUT "$CRLF********** Hits / hour ********** $CRLF";
    if ($pdesc eq 1) {
	$desctxt = "This shows the number of Hits per hour. Any sudden drops or increases in traffic can be due to web pounders stealing bandwidth, or an effective Denial of Service.";
	print OUT "$desctxt$CRLF";
    }

    sumhash (\%s7);
    #print OUT "Totally $sum and $uniq unique.$CRLF";
    printf OUT "%7s  %9s$CRLF",  'Hour', 'Hits';
    #foreach $k (sort keys %s7)
    for ($k=0;$k<24;$k++)
    {
	@_ = split "�", $k;
	$hits = $s7{sprintf("%02d", $k)};
	if ($hits eq '') { $hits = '0'};
	printf (OUT "%7d  %9s  %-50s$CRLF",  $_[0], $hits, "*" x ($hits / ($hrmax+1) * 40));
    }
    

    # Dangerous files...
    sumhash(\%s3);
    if (($uniq eq 0) && (!defined $opt_m)) {
	print OUT "$CRLF********** Successful attempts to retrieve \'Dangerous\' files ********** $CRLF";
	if ($pdesc eq 1) {
	    $desctxt = "This could indicate successful attempts to retrieve sensitive files, or possibly execute system commands in the server.";
	    print OUT "$desctxt$CRLF";
	}

    #sumhash (\%s3);
	if ($uniq gt 0) {
	    print OUT "This could inidicate a serious security breach.$CRLF";
	    print OUT "Totally $sum and $uniq unique.$CRLF";
	    printf OUT "%7s  %-15s  %-50s$CRLF",  'Count', 'Src IP', 'URL' ;
	    foreach $k (sort {$s3{$b} <=> $s3{$a}} keys %s3 )
	    {
		@_ = split "�", $k;
		printf (OUT "%7d  %-15s  %-50s$CRLF",  $s3{$k},$_[0], $_[1]);
	    }
	} else {
	    printf OUT "None. $CRLF";
	}
    }
    
    # Unauthorized
    sumhash(\%s2);
    if (($uniq eq 0) && (!defined $opt_m)) {
	print OUT "$CRLF********** Users who have accessed protected pages ********** $CRLF";
	if ($pdesc eq 1) {
	    $desctxt = "This shows all users who have accessed password protected pages. Users whi repeatedly access the same page could indicate password brute force attempts.";  
	    printf OUT "$desctxt\n";
	}
	#sumhash (\%s2);
	if ($uniq gt 0) {
	    print OUT "Totally $sum and $uniq unique.$CRLF";
	    printf OUT  "%7s  %5s  %-15s  %-9s %s$CRLF", 'Count', 'Status', 'Src IP', 'User', 'URL';
	    foreach $k (sort {$s2{$b} <=> $s2{$a}} keys %s2 )
	    {
		@_ = split "�", $k;
		printf(OUT  "%7d  %5s   %-15s  %-9s %s$CRLF",  $s2{$k},$_[0], $_[1], $_[3], $_[2]);
	    }
	} else {
	    printf OUT "None. $CRLF";
	}
    }


    sumhash (\%s10);
    if (($uniq gt 0)) {    
	print OUT "$CRLF********** Logged in Users **********$CRLF";
	if ($pdesc eq 1) {
	    $desctxt = "Lists all users who have successfully logged in. Verify that the users are valid.";
	    printf OUT "$desctxt\n";
	}
	
	#sumhash (\%s10);
	if ($uniq gt 0) {   
	    print OUT "Totally $sum and $uniq unique.$CRLF";
	    printf(OUT "%9s  %-15s$CRLF",  'Count', 'User');
	    foreach $k (sort {$s10{$b} <=> $s10{$a}} keys %s10 )
	    {
		@_ = split "�", $k;
		printf(OUT "%9d  %-15s$CRLF",  $s10{$k},$_[0]);
	    }
	} else {
	    if ($userundef gt 0) {
		printf OUT "Not Available - not logged in log file.$CRLF";
	    } else {
		printf OUT "None. $CRLF";
	    }
	}
    } 
    else {
	print OUT "uniq = $uniq. Nou Users";
	print OUT $opt_m;
    }


    sumhash(\%s1);
    if (($uniq gt 0) && (! defined $opt_m)) {
	print OUT "$CRLF********** Logged in users per IP-address (excl Anonymous) **********$CRLF";
	if ($pdesc eq 1) {
	    $desctxt = "Shows the source IP-addresses of successful logins. Make sure all addresses are valid or can be derived.";
	    print OUT "$desctxt\n";
	}

	#sumhash (\%s1);
	if ($uniq gt 0) {
	    print OUT "Totally $sum and $uniq unique.$CRLF";
	    printf OUT "%9s  %-15s  %-15s  %s$CRLF",  'Count', 'User', 'Src-IP', 'FQDN';
	    foreach $k (sort {$s1{$b} <=> $s1{$a}} keys %s1 )
	    {
		@_ = split "�", $k;
		printf OUT "%9d  %-15s  %-15s  %s$CRLF",  $s1{$k},$_[0], $_[1], $sip{$_[1]};
	    }
	} else {
	    if ($userundef gt 0) {
		printf OUT "Not Available - not logged in log file.$CRLF";
	    } else {
		printf OUT "None. $CRLF";
	    }
	}
    }

    # Count of all Statuscodes...
    print OUT "$CRLF********** Count of HTTP statuscodes ********** $CRLF";
    if ($pdesc eq 1) {
	$desctxt = "Shows all Statuscodes. If 404's are missing, this probably indicates a fualty error-page. Excessive 4xx and 5xx codes can indicate problems that need further investigation.";
	print OUT "$desctxt\n";
    }
    sumhash (\%s5);
    
    print OUT "Totally $sum and $uniq unique.$CRLF";
    print OUT "    Count     ( % )     HTTP-Status $CRLF";
    foreach $k (sort keys %s5 )
    {
	@_ = split "�", $k;
	#printf(OUT "Count: %9d (%6.2f%%) HTTP Status: %-4d  %s$CRLF",  $s5{$k},($s5{$k}*100/$sum), $_[0], $STATCODE{$_[0]});
	printf(OUT "%9d (%6.2f%%)    %4s %s$CRLF",  $s5{$k},($s5{$k}*100/$sum), $_[0], $STATCODE{$_[0]});
    }

    # Count of all HTTP Methods...
    print OUT "$CRLF********** Count of HTTP Methods ********** $CRLF";
    if ($pdesc eq 1) {
	$desctxt = "Shows all attempted Methods. GET and POST are most common and normal. Others can indicate reconnossaince attempts, or manipulation attempts, however there are many Methods which are legitimate, depending on server and configuration.";
	print OUT "$desctxt\n";
    }
    sumhash (\%s19);
    print OUT "Totally $sum and $uniq unique.$CRLF";
    print OUT "    Count     ( % )     HTTP-Method $CRLF";
    foreach $k (sort {$s19{$b} <=> $s19{$a}} keys %s19 )
    {
	@_ = split "�", $k;
	printf(OUT "%9d (%6.2f%%)     %s$CRLF",  $s19{$k}, ($s19{$k}*100/$sum),    $k,);
    }
        
    # Count of all HTTP Versions...
    print OUT "$CRLF********** Count of HTTP Versions ********** $CRLF";
    if ($pdesc eq 1) {
        $desctxt = "There are basically two (or maybe three) HTTP versions: HTTP/1.0, HTTP/1.1, HTTP/0.9. Anything else is either a faulty browser or reconnossaince / manipulation attempts. Keep an eye on addresses generating invalid HTTP versions.";
	print OUT "$desctxt\n";
    }
    
    sumhash (\%s6);
    if ($uniq gt 0) {
	print OUT "Totally $sum and $uniq unique.$CRLF";
	print OUT "    Count     ( % )    HTTP-Version $CRLF";
	foreach $k (sort {$s6{$b} <=> $s6{$a}} keys %s6 )
	{
	    @_ = split "�", $k;
	    #printf(OUT "Count: %9d %s  %s %s$CRLF",  $s6{$k}, ($s6{$k}*100/$sum), $_[0]);
	    printf(OUT "%9d (%6.2f%%)    %s$CRLF",  $s6{$k}, ($s6{$k}*100/$sum), $_[0]);
	}
    
	# List illegal HTTP Versions...
	sumhash(\%s61);
	if ((($uniq eq 0) && (! defined $opt_m)) || ($uniq gt 0)) {
	    print OUT "$CRLF********** List illegal HTTP Versions ********** $CRLF";
	    if ($pdesc eq 1) {
		$desctxt = "This list all requests done without a valid HTTP versoin. This could indicate attempts to connect via telnet or other tcp based mechanism, usually indicating reconnosaince. Keep an eye on addresses in this list.";
		print OUT "$desctxt\n";
	    }
	
	    sumhash (\%s61);
	    if ($uniq gt 0) {
		print OUT "Totally $sum and $uniq unique.$CRLF";
		printf(OUT "%9s %-25s %-15s %s %-s$CRLF", 'Count' , 'HTTP String',  'IP', 'FQDN');
		foreach $k (sort {$s61{$b} <=> $s61{$a}} keys %s61 )
		{
		    @_ = split "�", $k;
		    printf(OUT "%9s %-25s %-15s %s  %s$CRLF",  $s61{$k}, $_[0], $_[1], resolve($_[1]));
		}
	    } else {
		printf OUT "None. $CRLF";
	    }
	}
    } else {
	if ($httpverundef gt 0) {
	    printf OUT "Not Available - not logged in log file.$CRLF";
	}
    }

    # List the Top HIT'ers
    $xx = 1;
    sumhash(\%iptab);
    print OUT "$CRLF$CRLF********** Top " . ( ($uniq > $topmax) ? $topmax : $uniq)  . " HIT\'ers **********$CRLF";
    if ($pdesc eq 1) {
        $desctxt = "This list shows the addresses requesting the most pages (hits). Each hit uses resources - cpu and bandwidth. Top IP's in this list can indicate anything from a valid interested user, to a spider crawling your site looking for security holes. Or someone asking repetitive querys to your database. Keep an eye on the top IP's.";
        print OUT "$desctxt\n";
    }

    #sumhash (\%iptab);
    #print OUT ($uniq >= $topmax) ? $topmax : $uniq;
    print OUT "Totally $sum and $uniq unique.$CRLF";
    printf(OUT "%4s %8s   %7s  %-15s  %-30s$CRLF", 'Rank', '%', 'Count', 'IP', 'FQDN');
    foreach $k (sort {$iptab{$b} <=> $iptab{$a}} keys %iptab )
    {
	@_ = split "�", $k;
	printf(OUT "%4d (%6.2f%%)  %7d  %-15s  %-30s$CRLF", $xx, ($iptab{$k}*100/$sum), $iptab{$k},$_[0], resolve($_[0]));
	if ($xx++ == $topmax) { last; }
    }
    
    
    # List attempts to access non-existing pages
    print OUT "$CRLF$CRLF********** Access attempts generating 403/404 messages **********$CRLF";
    if ($pdesc eq 1) {
	$desctxt = "This list indicates the top requests for nonexistent oages. The tops on this list either indicate faulty links in the sites HTML code, or you are being hit by malicious worms.  ";
        print OUT "$desctxt\n";
    }

    sumhash (\%s01);
    if ($uniq gt 0) {
	print OUT "Totally $sum and $uniq unique.$CRLF";
	printf(OUT "%7s  %7s  %-15s$CRLF",  'Count', 'Status', 'URL');
	foreach $k (sort {$s01{$b} <=> $s01{$a}} keys %s01 )
	{
	    @_ = split "�", $k;
	    printf(OUT "%7d  %7d  %-15s$CRLF",  $s01{$k},$_[0], $_[1]);
	}
	
	print OUT "$CRLF$CRLF********** Top $topmax IP\'s generating 403/404 **********$CRLF";
	if ($pdesc eq 1) {
	    
	    $desctxt = "This list shows the addresses requesting the most nonexistent pages (hits). Each request for a nonexistent page can mean one or more of several things: 1) Someone is actively looking for known security holes on your site. 2) There are faulty links in your HTML code. 3) You are being hit by malicious selfpropagating worms. 4) Someone is preforming reconnossaince of your site. And failing. Bottom line? Top hitters on this list could actively be looking for security holes - monitor their IP's";
	    print OUT "$desctxt\n";
	}
	$xx = 1;
	sumhash (\%s02);
	print OUT "Totally $sum and $uniq unique.$CRLF";
	printf(OUT "%4s %7s   %-15s  %s$CRLF",  'Rank', "Count", "IP-Address", "FQDN");
	foreach $k (sort {$s02{$b} <=> $s02{$a}} keys %s02 )
	{
	    @_ = split "�", $k;
	    #printf(OUT "Count:  %7d  IP: %-15s (%s)$CRLF",  $s02{$k},$_[0], $sip{$_[0]})
	    printf(OUT "%4d %7d   %-15s  %s$CRLF",  $xx, $s02{$k},$_[0], $sip{$_[0]});
	    if ($xx++ == $topmax) { last; }
	}
	
	print OUT "$CRLF$CRLF********** Top $topmax Files per IP genererating 403/404 **********$CRLF";
	if ($pdesc eq 1) {
	    $desctxt = "Is any single IP hammering your site for a non-existent page? Possible Denial-of-Service attempt, or faulty site configuration.";
	    print OUT "$desctxt\n";
	}
	$xx = 1;
	sumhash (\%s0);
	print OUT "Totally $sum and $uniq unique.$CRLF";
	print OUT "This could inidicate either faultly links on your site, or$CRLF";
	print OUT "a perpetrator looking for vulnerabilities.$CRLF";
	printf(OUT "%4s %7s  %-15s  %s$CRLF", 'Rank', 'Count', 'Src IP', 'URL' );
	foreach $k (sort {$s0{$b} <=> $s0{$a}} keys %s0 )
	{
	    @_ = split "�", $k;
	    printf(OUT "%4d %7d  %-15s  %s$CRLF",  $xx, $s0{$k},$_[0], $_[1]);
	    if ($xx++ == $topmax) { last; }
	}
    } else {
        printf OUT "None. $CRLF";
    }
    
	
    
    # 5xx Status
    sumhash(\%s42);
    if ((($uniq eq 0) && (!defined $opt_m)) || ($uniq gt 0)) {
	print OUT "$CRLF********** Top $topmax IP\'s causing Server Errors (5xx) ********** $CRLF";
	if ($pdesc eq 1) {
	    $desctxt = "Errors generated here are on the server. This could either be manipulation attempts, or excessive database access. Or just a misconfiguration of the web server.";
	    print OUT "$desctxt\n";
	}
	
	sumhash (\%s42);
	if ($uniq > 0) {
	    $xx = 1;
	    print OUT "Totally $sum and $uniq unique.$CRLF";
	    printf OUT "%7s  %-7s  %-15s %s$CRLF",  'Count', 'Status', 'Src IP', 'FQDN';
	    foreach $k (sort {$s42{$b} <=> $s42{$a}} keys %s42 )
	    {
		@_ = split "�", $k;
		printf(OUT "%7d  %-7d  %-15s %s$CRLF",  $s42{$k},$_[0], $_[1], $sip{$_[1]});
		if ($xx++ == $topmax) { last; }
	    }
	    
	    
	    # 5xx Status
	    print OUT "$CRLF********** Top $topmax URL\'s causing Server Errors (5xx) ********** $CRLF";
	    if ($pdesc eq 1) {
		$desctxt = "Errors generated here are on the server. This could either be manipulation attempts, or excessive database access. Or just a misconfiguration of the web server. If the same URL is causing the errors, this might indicate the source of the problem. Or possibly a security breach.";
		print OUT "$desctxt\n";
	    }
	    
	    $xx = 1;
	    sumhash (\%s4);
	    print OUT "Totally $sum and $uniq unique.$CRLF";
	    printf OUT "%7s  %-7s  %-20s$CRLF",  'Count', 'Status', 'URL';
	    foreach $k (sort {$s4{$b} <=> $s4{$a}} keys %s4 )
	    {
		@_ = split "�", $k;
		printf(OUT "%7d  %-7d  %-20s$CRLF",  $s4{$k},$_[0], $_[1]);
		if ($xx++ == $topmax) { last; }
	    }
	    
	    print OUT "$CRLF********** Top $topmax URL\'s & IP\'s causing Server Errors (5xx) ********** $CRLF";
	    if ($pdesc eq 1) {
		$desctxt = "Is any single IP using a specific URL to wreak havoc on your web server?";
		print OUT "$desctxt\n";
	    }
	    
	    $xx = 1;
	    sumhash (\%s41);
	    print OUT "Totally $sum and $uniq unique.$CRLF";
	    printf OUT "%7s  %-7s  %-15s  %s$CRLF", 'Count', 'Status', 'Src IP', 'URL' ;
	    foreach $k (sort {$s41{$b} <=> $s41{$a}} keys %s41 )
	    {
		@_ = split "�", $k;
		printf(OUT "%7d  %-7d  %-15s  %s$CRLF",  $s41{$k},$_[0], $_[2], $_[1]);
		if ($xx++ == $topmax) { last; }
	    }
	} else {
	    printf OUT "None. $CRLF";
	}
    }


    # Binary / un-printable data in URL's
    sumhash (\%s45);
    if ((($uniq eq 0) && (!defined $opt_m)) || ($uniq gt 0)) {
	print OUT "$CRLF********** URL's containing binary data ********** $CRLF";
	if ($pdesc eq 1) {
	    $desctxt = "This is a no-no. Anything listed here should not happen under normal circumstances, since binary data is not allowed in a URL. It should always be encoded in some way. Entries gere could indicate attempts to cause buffer overflows and security breaches. There is a possible false positive with some obscure browsers sending odd binary data, but it is not common. Check these IPs!";
	    print OUT "$desctxt\n";
	}
	
	sumhash (\%s45);
	if ($uniq gt 0) {
	    print OUT "Totally $sum and $uniq unique.$CRLF";
	    printf OUT "%7s  %-15s  %-50s$CRLF",  'Count', 'Src IP', 'URL' ;
	    foreach $k (sort {$s45{$b} <=> $s45{$a}} keys %s45 )
	    {
		@_ = split "\#\#", $k;
		printf (OUT "%7d  %-15s  %-50s$CRLF",  $s45{$k},$_[0], $_[1]);
	    }
	} else {
	    printf OUT "None Found. $CRLF";
	}
    }

    # Top Referers
    $xx = 1;
    print OUT "$CRLF********** Top $topmax Referers ********** $CRLF";
    if ($pdesc eq 1) {
        $desctxt = "This is mostly for reference, but if your server is vulnerable, someone might have put a link to it on their site. And you will then see where they are coming from (i.e. refered to).";
        print OUT "$desctxt\n";
    }

    sumhash (\%s11);
    if ($uniq > 0 ) {
	print OUT "Totally $sum and $uniq unique.$CRLF";
	printf OUT "%7s  %-50s$CRLF", 'Count', 'Referer' ;
	foreach $k (sort {$s11{$b} <=> $s11{$a}} keys %s11 )
	{
	    @_ = split "�", $k;
	    printf(OUT "%7d  %-50s $CRLF",  $s11{$k},$_[0]);
	    if ($xx++ == $topmax) { last; }
	}
    } else {
        if ($refererundef gt 0) {
            printf OUT "Not Available - not logged in log file.$CRLF";
        } else {
            printf OUT "None. $CRLF";
        }
    }
    

    # Top Blank referers
    $xx = 1;
    print OUT "$CRLF********** Top $topmax Blank Referers ********** $CRLF";
    if ($pdesc eq 1) {
        $desctxt = "This could indicate information-harvesters fetching pages through an automated tool. It would also show users coming through bookmarked pages.";
        print OUT "$desctxt\n";
    }

    sumhash (\%s131);
    if ($uniq > 0 ) {
	print OUT "Totally $sum and $uniq unique.$CRLF";
	printf OUT "%7s  %-15s %-12s $CRLF", 'Count', ,'IP', 'Referer' ;
	foreach $k (sort {$s131{$b} <=> $s131{$a}} keys %s131 )
	{
	    @_ = split "�", $k;
	    printf(OUT "%7d  %-15s %-12s $CRLF",  $s131{$k},$_[0], $_[1]);
	    if ($xx++ == $topmax) { last; }
	}
    } else {
        if ($refererundef gt 0) {
            printf OUT "Not Available - not logged in log file.$CRLF";
        } else {
            printf OUT "None. $CRLF";
        }
    }
    
    # Top Browsers
    $xx = 1;
    print OUT "$CRLF********** Browsers ********** $CRLF";
    if ($pdesc eq 1) {
        $desctxt = "This is mostly for reference. The most common browsers are listed in their various formats. However, there are tools which use non-common  brosers. Use of such can be indicative of reconnossaince of the site. Be observant of the top and bottom entries in this list."; 
        print OUT "$desctxt\n";
    }

    sumhash (\%s12);
    if ($uniq gt 0 ) {
	print OUT "Totally $sum and $uniq unique.$CRLF";
	printf OUT "%7s  %-50s$CRLF", 'Count', 'Browser' ;
	foreach $k (sort {$s12{$b} <=> $s12{$a}} keys %s12 )
	{
	    @_ = split "�", $k;
	    printf(OUT "%7d  %-50s $CRLF",  $s12{$k},$_[0]);             
	    #if ($xx++ == $topmax) { last; }
	}
    } else {
	printf OUT "Not Available$CRLF";
    }

    # Check for Cookie Manipulation
    sumhash(\%s14);
    if ((($uniq eq 0) && (!defined $opt_m)) || ($uniq gt 0)) {
	$xx = 1;
	print OUT "$CRLF********** Same Cookie from different IP-addresses ********** $CRLF";
	if ($pdesc eq 1) {
	    $desctxt = "This could inidicate attempted session hijacking (unlikely, but serious), or users coming via a non-ip session aware proxy (likely, and not so serious).";
	    print OUT "$desctxt\n";
	}
	
	#sumhash (\%s14);
	if ($uniq gt 0) {
	    print OUT "Totally $sum and $uniq unique. Showing at maximum the top $topmax.$CRLF";
	    printf OUT "%9s %-15s %s$CRLF", 'Count', 'IP', 'FQDN';
	    #foreach $k (sort {$s14{$b} <=> $s14{$a}} keys %s14)
	    $old = '';
	    foreach $k (sort keys %s14)
	    {
		#print "\$k: $k\n";
		@_ = split "�", $k;
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
	    if ($cookieundef gt 0) {
		printf OUT "Not Available - not logged in log file.$CRLF";
	    } else {
		printf OUT "None. $CRLF";
	    }
	}
    }

    sumhash(\%s21);
    if ((($uniq eq 0) && (!defined $opt_m)) || ($uniq gt 0)) {
	print OUT "$CRLF********** Cross Site Scripting Attempts per IP *********$CRLF";
	if ($pdesc eq 1) {
	    $desctxt = "Anything listed here could indicate Cross Site Scripting attempts. If successfull, they could allow stealing of your users credentials, and thus alleviating unauthorized access. Successfull attempts listed here must be examined further.";
	    print OUT "$desctxt\n";
	}
	#sumhash (\%s21);
	if ($uniq gt 0) {
	    print OUT "Totally $sum and $uniq unique.$CRLF";
	    printf OUT "%7s %-15s %-40s %-15s$CRLF", 'Count', 'IP', 'URL', 'FQDN';
	    foreach $k (sort {$s21{$b} <=> $s21{$a}} keys %s21)
	    {
		($ip, $url) = split "�", $k;
		printf OUT "%7d %-15s %-40s %-15s$CRLF",  $s21{$k}, $ip, $url, resolve($ip);
	    }
	} else {
	    print OUT "None found.$CRLF";
	}
    }

    # Check for Directory scanning / Listing
    sumhash(\%s15);
    if ((($uniq gt 0) && (!defined $opt_m)) || ($uniq gt 0)) {
	$xx = 1;
	print OUT "$CRLF********** Unsuccessful Subdirectory Listing Attempts ********** $CRLF";
	if ($pdesc eq 1) {
	    $desctxt = "This indicates reconnosaince buy attempting to list subdirectories of the site. The perpetrator is presumably looking for misconfigured default pages or trying to view source code.";
	}
	#sumhash (\%s15);
	if ($uniq gt 0) {
	    print OUT "Totally $sum and $uniq unique.$CRLF";
	    #print OUT "This could inidicate attempted session hijacking.$CRLF";
	    printf OUT "%7s %7s %-30s %-15s %-4s$CRLF", 'Count', 'Status', 'URL', 'IP', 'FQDN';
	    foreach $k (sort {$s15{$b} <=> $s15{$a}} keys %s15)
	    {
		@_ = split "�", $k;
		printf(OUT "%7d %7s %-30s %-15s %s$CRLF",  $s15{$k},$_[2], $_[1], $_[0], resolve($_[0]));
		if ($xx++ == $topmax) { last; }
	    }
	} else {
	    print OUT "None found.$CRLF";
	}
    }
    
    sumhash(\%s151);
    if ((($uniq eq 0) && (!defined $opt_m)) || ($uniq gt 0)) {
	print OUT "$CRLF********** Unsuccessful Subdir attempts per IP ********$CRLF";
	if ($pdesc eq 1) {
	    $desctxt = "If the Top IP's generate errors on many subdirectories, it is a probable attempted (and possibly succeeded) reconnossaince sweep.";
	    print OUT "$desctxt\n";
	}
	
	#sumhash (\%s151);
	if (uniq gt 0) {
	    foreach $k (sort {$s151{$b} <=> $s151{$a}} keys %s151) 
	    {
		printf(OUT "Count: %-10s IP: %-15s %s$CRLF", $s151{$k}, $k, resolve($k));
		foreach $l (sort {$s15{$b} <=> $s15{$a}} keys %s15) {
		    ($ip2, $url2, $status2) = split "�", $l;
		    if ($ip2 eq "$k") {
			printf OUT "  Subdir: %7s  %4d  %s $CRLF", $s15{$l}, $status2, $url2;
		    }
		}
		print OUT "$CRLF";
	    } 
	} else {
	    print OUT "None found.$CRLF";
	}
    }


    # List attempted form manipulation
    sumhash(\%s16);
    if ((($uniq eq 0) && (!defined $opt_m)) || ($uniq gt 0)) {
	$xx = 1;
	print OUT "$CRLF********** Suspected Form Data Manipulation ********** $CRLF";
	if ($pdesc eq 1) {
	    $desctxt = "This is basically only valid of the site has a database which can be accessed via SQL. It could indicate attempts to manipluate queries to your database, but could also be a false positive. Needs verification to rule out unauthorized access.";
	    printf OUT "$desctxt\n";
	}
	
	#sumhash (\%s16);		     
	if ($uniq gt 0) {
	    print OUT "Totally $sum and $uniq unique.$CRLF";
	    print OUT "This could inidicate attempted unauthorized database access.$CRLF";
	    printf OUT "%7s %-30s %-15s %-15s %-20s$CRLF", 'Count', 'Query', 'IP', 'FQDN' ;
	    foreach $k (sort {$s16{$b} <=> $s16{$a}} keys %s16)
	    {
		@_ = split "�", $k;
		printf(OUT "%7d %-30s %-15s %-15s$CRLF",  $s16{$k}, $_[1], $_[0], resolve($_[0]));
		if ($xx++ == $topmax) { last; }
	    }
	} else {
	    print OUT "None found.$CRLF";
	}
    }

    sumhash(\%s17);
    if ((($uniq eq 0) && (!defined $opt_m))  || ($uniq gt 0)) {
	# List attempted Anonymous Proxy Scans
	$xx = 1;
	print OUT "$CRLF********** Attempts to locate Proxy ********** $CRLF";
	if ($pdesc eq 1) {
	    $desctxt = "This indicates attempts to locate and possibly use the site to stage further attacks. If the proxy attempts are successful, the site could be used to relay spam or participate in illegitimate activities.";
	    printf OUT "$desctxt\n";
	}
	
	#sumhash (\%s17);
	if ($uniq gt 0) {
	    print OUT "Totally $sum and $uniq unique.$CRLF";
	    printf OUT "%7s %6s %-40s %-15s %-15s %s$CRLF", 'Count', 'Status', 'Request', 'IP', 'FQDN';
	    foreach $k (sort {$s17{$b} <=> $s17{$a}} keys %s17)
	    {
		@_ = split "�", $k;
		printf(OUT "%7d %6d %-40s %-15s %s$CRLF",  $s17{$k}, $_[1], $_[2], $_[0], resolve($_[0]));
		if ($xx++ == $topmax) { last; }
	    }
	} else {
	    print OUT "None found.$CRLF";
	}
    }


    # List exceedingly Long URL's
    sumhash(\%s18);
    if ((($uniq eq 0) && (!defined $opt_m)) || ($uniq gt 0)){
	$xx = 1;
	print OUT "$CRLF********** Exceedingly Long URL's ********** $CRLF";
	if ($pdesc eq 1) {
	    $desctxt = "This indicates attempts to locate and possibly execute a buffer overflow. If sucessful a perpetrator could have full system access. This in not common, but rather there are long URL's on the site which falsely trigger this.";
	    printf OUT "$desctxt\n";
	}
	
	sumhash (\%s18);
	if ($uniq gt 0) {
	    print OUT "Totally $sum and $uniq unique.$CRLF";
	    printf OUT "%7s %6s %10s  %-15s %-30s %-15s$CRLF", 'Count', 'Status', 'Length', 'URL', 'FQDN' ;
	    foreach $k (sort {$s18{$b} <=> $s18{$a}} keys %s18)
	    {
		@_ = split "�", $k;
		printf(OUT "%7d %6s %10s  %-30s\n%26s %-15s %s $CRLF",  $s18{$k}, $_[3], $_[2], $_[0] ,'', $_[1], resolve($_[1]));
		if ($xx++ == $topmax) { last; }
	    }
	} else {
	    print OUT "None found.$CRLF";
	}
    }
    
    close OUT;
    slog("Done printing text output");

}



sub printxml {
    
    #my $output = new IO::File(">output.xml");
    my $output = new IO::File(">$outfile");
    #print STDERR "XML Outfile: $outfile\n";
    
    $w = new XML::Writer(OUTPUT => $output, NEWLINES => 0, DATA_INDENT => 2, DATA_MODE => 1);
    #print $output ' ';  # Fixup because otherwise the first character is lost!
    #$w->characters();
    #print $output; 
    $w->xmlDecl('UTF-8',"yes");
    $w->comment('Secsrch ' . localtime());
    #$w->doctype("secsrch");
    
    # Check if results are OK, before mailing report
    if ($numlines eq $logformat{'Unknown'}) {
	exit 99;
    }
    slog('Printing XML output');
    $w->startTag('report', 'version' => '1.0');
    $w->startTag('reportinfo');
    $w->dataElement('version', $VERSION);
    $w->dataElement('logdatestart', $mindate);
    $w->dataElement('logdateend', $maxdate);
    $w->dataElement('title', "Security Log File Analysis");
    $w->dataElement('analysisstart', " " . localtime());
    $w->startTag('inputfiles');
    foreach $f (@list) {
	$w->dataElement('file',$f);
    }
    $w->endTag('inputfiles');

    $w->dataElement('outputfile', $outfile);
    $w->dataElement('execstart', $starttimetext);
    $w->dataElement('execstop', localtime(). "");
    $w->dataElement('rowsanalysed',$numlines);
    $w->dataElement("rowsanalysedpersec", $numlines / (time - $starttime + 1));
    $w->dataElement('nripaddr',$numip);
    $w->dataElement('perf',  $numlines / (time - $starttime + 1));
    $w->dataElement('nameresoff', $opt_N);
    $w->endTag('reportinfo');
    $w->startTag('logformats');
    #$w->characters(prntx('title','Logformats'));
    

    foreach $x (keys %logformat) {
	$w->startTag("rec");
	$w->dataElement('format', $x);
	$w->dataElement('nrfound', $logformat{$x});
	$w->endTag("rec");
    }

    $w->endTag('logformats');


    slog("Nr of Analyzed rows: $numlines");
    slog("Rows/sec: " . $numlines / (time - $starttime + 1));
    #printf OUT "nr of analyzed rows/second: %7d $CRLF", $numlines / (time - $starttime + 1);

    
    # Show number of hits/hour
    $w->startTag("hitsperhour");
    $w->dataElement('title','Hits per hour');
    $w->dataElement('desc', 'This shows the number of Hits per hour. Any sudden drops or increases in traffic can be due to web pounders stealing bandwidth, or an effective Denial of Service.');
    sumhash (\%s7);
    #print OUT "Totally $sum and $uniq unique.$CRLF";
    #printf OUT "%7s  %9s$CRLF",  'Hour', 'Hits';
    #foreach $k (sort keys %s7)
    for ($k=0;$k<24;$k++)
    {
	@_ = split "�", $k;
	$hits = $s7{sprintf("%02d", $k)};
	if ($hits eq '') { $hits = '0'};
	#printf (OUT "  <hits hour=\"%d\">%s</hits>\n",  $_[0], $hits);
	$w->startTag("rec");
	$w->dataElement('hour', $_[0]);
	$w->dataElement('hits', $hits);
	$w->endTag("rec");
    }
        
    $w->endTag("hitsperhour");


    # Dangerous files...
    sumhash (\%s3);
    $w->startTag('dangerousfiles', 
		 'total' => $sum,
		 'uniq' => $uniq);
    $w->dataElement('title', 'Successful attempts to retrieve Dangerous files');
    $w->dataElement('desc', 'This could indicate successful attempts to retrieve sensitive files, or possibly execute system commands in the server.');

    foreach $k (sort {$s3{$b} <=> $s3{$a}} keys %s3 )
    {
	@_ = split "�", $k;
	$w->startTag('rec');
	$w->dataElement ('count',$s3{$k});
	$w->dataElement('srcip',$_[0]);
	$w->dataElement('url',$_[1]);
	$w->endTag('rec');
    }
    $w->endTag(dangerousfiles);

    
    # Unauthorized - Users who have accessed protected pages 
    sumhash (\%s2);
    $w->startTag("unauthorized", 
		 'total' => $sum, 
		 'uniq' => $uniq);
    $w->dataElement('title', 'Users who have accessed protected page');
    $w->dataElement('desc','This shows all users who have accessed password protected pages. Users whi repeatedly access the same page could indicate password brute force attempts.');
    foreach $k (sort {$s2{$b} <=> $s2{$a}} keys %s2 )
    {
	@_ = split "�", $k;
	$w->startTag('rec');
	$w->dataElement('count',$s2{$k});
	$w->dataElement('status',$_[0]);
	$w->dataElement('srcip',$_[1]);
	$w->dataElement('user',$_[3]);
	$w->dataElement('url',$_[2]);
	$w->endTag('rec');
    }
    $w->endTag('unauthorized');    


    # Logged in Users
    sumhash (\%s10);
    
    $w->startTag('logged_in_users', 'total' => $sum, 'uniq' => $uniq);
    $w->dataElement('title','Logged in users');
    $w->dataElement('desc','Lists all users who have successfully logged in. Verify that the users are valid.');
    foreach $k (sort {$s10{$b} <=> $s10{$a}} keys %s10 )
    {
	@_ = split "�", $k;
	$w->startTag('rec');
	$w->dataElement('user',$_[0]);
	$w->dataElement('count', $s10{$k});
	$w->endTag('rec');

    }
    $w->endTag('logged_in_users');

    
    # Logged in users per IP-address (excl Anonymous) 
    sumhash (\%s1);
    $w->startTag('logged_in_users_per_ip', 'total' => $sum, 'uniq' => $uniq);
    
    $w->dataElement('title', 'Logged in user per IP-address');
    $w->dataElement('desc', 'Shows the source IP-addresses of successful logins. Make sure all addresses are valid or can be derived.');
    foreach $k (sort {$s1{$b} <=> $s1{$a}} keys %s1 )
    {
	@_ = split "�", $k;
	$w->startTag('rec');
	$w->dataElement('count',$s1{$k});
	$w->dataElement('user',$_[0]);
	$w->dataElement('srcip',$_[1]);
	$w->dataElement('fqdn',$sip{$_[1]});
	$w->endTag('rec');	
    }
    $w->endTag('logged_in_users_per_ip');
        

    # Count of all Statuscodes...
    sumhash (\%s5);
    $w->startTag('statuscodes', 'total' => $sum, 'uniq' => $uniq);
    $w->dataElement('title','Statuscodes');
    $w->dataElement('desc', 'Shows all Statuscodes. If 404\'s are missing, this probably indicates a fualty error-page. Excessive 4xx and 5xx codes can indicate problems that need further investigation.');
    foreach $k (sort keys %s5 )
    {
        @_ = split "�", $k;
        $w->startTag('rec');
	$w->dataElement('count',$s5{$k});
        $w->dataElement('status',$_[0]);
        $w->dataElement('statusname',$STATCODE{$_[0]});
        $w->endTag('rec');
    }
    $w->endTag('statuscodes');

    # Count of all HTTP Methods...
    sumhash (\%s19);
    $w->startTag('httpmethods', 'total' => $sum, 'uniq' => $uniq);
    $w->dataElement('title', 'List of HTTP methods found');
    $w->dataElement('desc', 'Shows all attempted Methods. GET and POST are most common and normal. Others can indicate reconnossaince attempts, or manipulation attempts, however there are many Methods which are legitimate, depending on server and configuration.');
    foreach $k (sort {$s19{$b} <=> $s19{$a}} keys %s19 )
    {
	@_ = split "�", $k;
	$w->startTag('rec');
	$w->dataElement('count',$s19{$k});
	$w->dataElement('method',$k);
	$w->endTag('rec');
    }
    $w->endTag('httpmethods');
    

    
    # Count of all HTTP Versions...
    sumhash (\%s6);

    $w->startTag('httpversions', 'total' => $sum, 'uniq' => $uniq);
    $w->dataElement('title', 'Count of HTTP-verssions');
    $w->dataElement('desc', 'There are basically two (or maybe three) HTTP versions: HTTP/1.0, HTTP/1.1, HTTP/0.9. Anything else is either a faulty browser or reconnossaince / manipulation attempts. Keep an eye on addresses generating invalid HTTP versions.');
    foreach $k (sort keys %s6 )
    {
	@_ = split "�", $k;
	$w->startTag('rec');
	$w->dataElement('count',$s6{$k});
	$w->dataElement('version',$_[0]);
        $w->endTag('rec');
    }
    $w->endTag('httpversions');
        
    
    # List illegal HTTP Versions...
    sumhash (\%s61);
    
    $w->startTag('illegalhttp', 'total' => $sum, 'uniq' => $uniq);
    $w->dataElement('title', 'Invalid HTTP-versions');
    $w->dataElement('desc', 'This list all requests done without a valid HTTP version. This could indicate attempts to connect via telnet or other tcp based mechanism, usually indicating reconnosaince. Keep an eye on addresses in this list.');
    foreach $k (sort keys %s61 )
    {
	@_ = split "�", $k;
	$w->startTag('rec');
	$w->dataElement('count',$s61{$k});
	$w->dataElement('httpstr',$_[0]);
	$w->dataElement('srcip',$_[2]);
	$w->dataElement('fqdn',resolve($_[2]));
	$w->endTag('rec');
    }
    $w->endTag('illegalhttp');

    
    # List the Top HIT'ers
    $xx = 1;
    sumhash(\%iptab);
    $w->startTag('tophitters', 'total' => $sum, 'uniq' => $uniq);
    $w->dataElement('title', 'List of Top Hitters');
    $w->dataElement('desc', 'This list shows the addresses requesting the most pages (hits). Each hit uses resources - cpu and bandwidth. Top IP\'s in this list can indicate anything from a valid interested user, to a spider crawling your site looking for security holes. Or someone asking repetitive querys to your database. Keep an eye on the top IP\'s.');
    foreach $k (sort {$iptab{$b} <=> $iptab{$a}} keys %iptab )
    {
	@_ = split "�", $k;
	$w->startTag('rec');
	$w->dataElement('rank',$xx);
	$w->dataElement('count',$iptab{$k});
	$w->dataElement('srcip',$_[0]);
	$w->dataElement('fqdn',resolve($_[0]));
	
	$w->endTag('rec');
	if ($xx++ == $topmax) { last; }
    }
    $w->endTag('tophitters');
    


    # List attempts to access non-existing pages

    sumhash (\%s01);
    $w->startTag('errors4xx', 'total' => $sum, 'uniq' => $uniq);
    $w->dataElement('title', 'Access attempts generating 4xx errors');
    $w->dataElement('desc', 'This list indicates the top requests for nonexistent pages. The tops on this list either indicate faulty links in the sites HTML code, or you are being hit by malicious worms.');
    foreach $k (sort {$s01{$b} <=> $s01{$a}} keys %s01 )
    {
	@_ = split "�", $k;
	$w->startTag('rec');
	$w->dataElement('count',$s01{$k});
	$w->dataElement('httpstatus',$_[0]);
	#prntx('url',uri_escape($_[1]));
	$w->dataElement('url',$_[1]);
	$w->endTag('rec');
    }
    
    $w->endTag('errors4xx');
    
    
    #Top IP\'s generating 403/404 **********
    $xx = 1;
    sumhash (\%s02);
    $w->startTag('top4xxerrorsperip', 'total' => $sum, 'uniq' => $uniq);
    $w->dataElement('title', 'Top 4xx errors per IP');
    $w->dataElement('desc','This list shows the addresses requesting the most nonexistent pages (hits). Each request for a nonexistent page can mean one or more ofseveral things\: 1) Someone is actively looking for known security holes on yoursite. 2) There are faulty links in your HTML code. 3) You are being hit by malicious selfpropagating worms. 4) Someone is performing reconnossaince of your site. And failing. Bottom line\? Top hitters on this list could actively be looking for security holes - monitor their IP\'s');    foreach $k (sort {$s02{$b} <=> $s02{$a}} keys %s02 )
    {
	@_ = split "�", $k;
	$w->startTag('rec');
	$w->dataElement('rank',$xx);
	$w->dataElement('count',$s02{$k});
	$w->dataElement('srcip',$_[0]);
	$w->dataElement('fqdn',$sip{$_[0]});
	$w->endTag('rec');
	if ($xx++ == $topmax) { last; }
    }
    $w->endTag('top4xxerrorsperip');
    
    
    #********** Top $topmax Files per IP genererating 403/404 *********
    $xx = 1;
    sumhash (\%s0);
    $w->startTag('top4xxerrorsperipurl', 'total' => $sum, 'uniq' => $uniq);
    $w->dataElement('title', 'Top 4xx errors per IP and URL');
    $w->dataElement('desc', 'Is any single IP hammering your site for a non-existent page? Possible Denial-of-Service attempt, or faulty site configuration.');
    foreach $k (sort {$s0{$b} <=> $s0{$a}} keys %s0 )
    {
	@_ = split "�", $k;
	$w->startTag('rec');
	$w->dataElement('rank',$xx);
	$w->dataElement('count',$s0{$k});
	$w->dataElement('srcip',$_[0]);
	$w->dataElement('url',$_[1]);

	$w->endTag('rec');
	if ($xx++ == $topmax) { last; }
    }
    $w->endTag('top4xxerrorsperipurl');
    

    # 5xx Status
    sumhash (\%s42);
    $w->startTag('top_5xx_errors_per_ip', 'total' => $sum, 'uniq' => $uniq);
    $w->dataElement('title', 'Top 5xx errors per IP');
    $w->dataElement('desc', 'Errors generated here are on the server. This could either be manipulation attempts, or excessive database access. Or just a misconfiguration of the web server.');
    $xx = 1;
    foreach $k (sort {$s42{$b} <=> $s42{$a}} keys %s42 )
    {
	@_ = split "�", $k;
	$w->startTag('rec');
	$w->dataElement('count',$s42{$k});
	$w->dataElement('status',$_[0]);
	$w->dataElement('srcip',$_[1]);
	$w->dataElement('fqdn',$sip{$_[1]});
	$w->endTag('rec');
	#if ($xx++ == $topmax) { last; }
    }
    
    $w->endTag('top_5xx_errors_per_ip');

    
    
    # 5xx Status
    #******* Top $topmax URL\'s causing Server Errors (5xx) 
    $xx = 1;
    sumhash (\%s4);
    $w->startTag('top_5xx_errors_per_url', 'total' => $sum, 'uniq' => $uniq);
    $w->dataElement('title', 'Top 5xx errors per URL');
    $w->dataElement('desc','Errors generated here are on the server. This couldeither be manipulation attempts, or excessive database access. Or just a misconfiguration of the web server. If the same URL is causing the errors, this might indicate the source of the problem. Or possibly a security breach.');
    foreach $k (sort {$s4{$b} <=> $s4{$a}} keys %s4 )
    {
	@_ = split "�", $k;
	$w->startTag('rec');
	$w->dataElement('count',$s4{$k});
	$w->dataElement('status',$_[0]);
	$w->dataElement('url',$_[1]);
	$w->endTag('rec');
	if ($xx++ == $topmax) { last; }
    }
    $w->endTag('top_5xx_errors_per_url');

    
    # Top URL\'s & IP\'s causing Server Errors (5xx) 
    $xx = 1;
    sumhash (\%s41);
    
    $w->startTag('top_5xx_errors_per_ip_url', 'total' => $sum, 'uniq' => $uniq);  
    $w->dataElement('title', 'Top 5xx errors per IP and URL');
    $w->dataElement('desc', 'Is any single IP using a specific URL to wreak havoc on your web server?');
    foreach $k (sort {$s41{$b} <=> $s41{$a}} keys %s41 )
    {
	@_ = split "�", $k;
	$w->startTag('rec');
	$w->dataElement('count',$s41{$k});
	$w->dataElement('status',$_[0]);
	$w->dataElement('srcip',$_[2]);
	$w->dataElement('url',$_[1]);
	$w->endTag('rec');
    }

    $w->endTag('top_5xx_errors_per_ip_url');


#### Addes URLS with binary data.

    # Binary / un-printable data in URL's
    sumhash (\%s45);
    $w->startTag('url_with_binary_data', 'total' => $sum, 'uniq' => $uniq);
    
    $w->dataElement('title', 'URL\'s containing binary data');
    $w->dataElement('desc', 'This is a no-no. Anything listed here should not happenunder normal circumstances, since binary data is not allowed in a URL. It should always be encoded in some way. Entries gere could indicate attempts to cause buffer overflows and security breaches. There is a possible false positive with some obscure browsers sending odd binary data, but it is not common. Check these IPs!');
    	
    if ($uniq gt 0) {
	foreach $k (sort {$s45{$b} <=> $s45{$a}} keys %s45 )
	{
	    @_ = split "\#\#", $k;
	    $w->startTag('rec');
	    $w->dataElement('count', $s45{$k});
	    $w->dataElement('srcip', $_[0]);
	    $w->dataElement('url', $_[1]);
	    $w->endTag('rec');

	}
    }

    $w->endTag('url_with_binary_data');

     
    # Top Referers
    $xx = 1;
    sumhash (\%s11);

    #if ($uniq > 0 ) {
    $w->startTag('topreferers', 'total' => $sum, 'uniq' => $uniq);
    $w->dataElement('title', 'Top Referers');
    $w->dataElement('desc', 'This is mostly for reference, but if your server is vulnerable, someone might have put a link to it on their site. And you will then see where they are coming from (i.e. refered to).');
    foreach $k (sort {$s11{$b} <=> $s11{$a}} keys %s11 )
    {
	@_ = split "�", $k;
	$w->startTag('rec');
	
	if ($_[0] =~ m/(.*?)\?(.*)/) {
	    $urlstr = $1; $uristr = uri_escape($2);
	} else {
	    #print "$_[0]\n";
	    $urlstr = $_[0]; $uristr = '';
	}

	$w->dataElement('count',$s11{$k});
	$w->dataElement('refurl',$urlstr);
	$w->dataElement('refuri',$uristr);
	$w->endTag('rec');
	#if ($xx++ == $topmax) { last; }
    }
    $w->endTag('topreferers');


    # Top Blank referers
    $xx = 1;
    sumhash (\%s131);
    $w->startTag('top_blank_ref', 'total' => $sum, 'uniq' => $uniq);
    $w->dataElement('title', 'Top Blank Referers');
    $w->dataElement('desc', 'This could indicate information-harvesters fetching pages through an automated tool. It would also show users coming through bookmarked pages.');
    
    foreach $k (sort {$s131{$b} <=> $s131{$a}} keys %s131 )
    {
	@_ = split "�", $k;
	#printf(OUT "%7d  %-15s %-12s $CRLF",  $s131{$k},$_[0], $_[1]);
	$w->startTag('rec');
	$w->dataElement('count', $s131{$k});
	$w->dataElement('srcip', $_[0]);
	$w->dataElement('url', $_[1]);
	$w->endTag('rec');
	
	if ($xx++ == $topmax) { last; }
    }

    #if ($refererundef gt 0) {
    #printf OUT "Not Available - not logged in log file.$CRLF";
    #} else {
    #printf OUT "None. $CRLF";
    #}

    $w->endTag('top_blank_ref');



    # Top Browsers
    $xx = 1;
    sumhash (\%s12);
    $w->startTag('topbrowsers', 'total' => $sum, 'uniq' => $uniq);
    $w->dataElement('title', 'Top Browsers used');
    $w->dataElement('desc', 'This is mostly for reference. The most common browsers are listed in their various formats. However, there are tools which use non-common  brosers. Use of such can be indicative of reconnossaince of the site. Be observant of the top and bottom entries in this list.');
    foreach $k (sort {$s12{$b} <=> $s12{$a}} keys %s12 )
    {
	@_ = split "�", $k;
	$w->startTag('rec');
	$w->dataElement('count',$s12{$k});
	$w->dataElement('browser',uri_escape($_[0]));
	$w->endTag('rec');
	#if ($xx++ == $topmax) { last; }
    }
    
    $w->endTag('topbrowsers');


    # Check for Cookie Manipulation
    $xx = 1;
    sumhash (\%s14);

    $w->startTag('cookiemanip', 'total' => $sum, 'uniq' => $uniq);
    $w->dataElement('title', 'Suspected Cookie Manipulation');
    $w->dataElement('desc', 'This could inidicate attempted session hijacking (unlikely, but serious), or users coming via a non-ip session aware proxy (likely, and not so serious).');
    
    $old = '';
    foreach $k (sort keys %s14)
    {
	@_ = split "�", $k;
	if ($old ne $_[0]) {
	    $co = (length($_[0]) > 60) ? substr($_[0],0,20) . ".. [ Truncated ] .." . substr($_[0], length($$_[0])-20,20) : $_[0];
	    $w->dataElement('cookie', $co);
	}
	$w->startTag('cookieinfo');
	$w->dataElement('count', $s14{$k});
	$w->dataElement('srcip', $_[1]);
	$w->dataElement('fqdn', resolve($_[1]));
	$w->endTag('cookieinfo');
	
	$old = $_[0];
	#if ($xx++ == $topmax) { last; }
    }
    $w->endTag('cookiemanip');



    #### Cross Site Scripting Attempts
    sumhash(\%s21);
    $w->startTag('xss_per_ip', 'total' => $sum, 'uniq' => $uniq);
    $w->dataElement('title', 'Cross Site Scripting Attempts per IP');
    $w->dataElement('desc', 'Anything listed here could indicate Cross Site Scripting attempts. If successfull, they could allow stealing of your users credentials, and thus alleviating unauthorized access. Successfull attempts listed here mustbe examined further.');
    
    foreach $k (sort {$s21{$b} <=> $s21{$a}} keys %s21)
    {
	($ip, $url) = split "�", $k;
	$w->startTag('rec');
        $w->dataElement('count', $s21{$k});
        $w->dataElement('srcip', $ip);
	$w->dataElement('url', $url);
	$w->dataElement('fqdn', resolve($ip));
        $w->endTag('rec');
    }

    $w->endTag('xss_per_ip');


    # Check for Directory scanning / Listing
    $xx = 1;
    sumhash (\%s15);
    $w->startTag('subdirlist', 'total' => $sum, 'uniq' => $uniq);
    $w->dataElement('title', 'Subdirectory Listing Attempts');
    $w->dataElement('desc','This indicates reconnosaince buy attempting to list subdirectories of the site. The perpetrator is presumably looking for misconfigureddefault pages or trying to view source code.');
    foreach $k (sort {$s15{$b} <=> $s15{$a}} keys %s15)
    {
	@_ = split "�", $k;
	$w->startTag('rec');
	$w->dataElement('count',$s15{$k});
	$w->dataElement('status',$_[2]);
	$w->dataElement('url',$_[1]);
	$w->dataElement('srcip',$_[0]);
	$w->dataElement('fqdn',resolve($_[0]));
	$w->endTag('rec');
	#if ($xx++ == $topmax) { last; }
    }
    $w->endTag('subdirlist');


    sumhash(\%s151);
    $w->startTag('unsuc_subdir_ip', 'total' => $sum, 'uniq' => $uniq);
    $w->dataElement('title', 'Unsuccessful Subdir attempts per IP');
    $w->dataElement('desc', 'If the Top IP\'s generate errors on many subdirectories, it is a probable attempted (and possibly succeeded) reconnossaince sweep.');
    foreach $k (sort {$s151{$b} <=> $s151{$a}} keys %s151)
    {
	foreach $l (sort {$s15{$b} <=> $s15{$a}} keys %s15) {
	    ($ip2, $url2, $status2) = split "�", $l;
	    if ($ip2 eq "$k") {
		$w->startTag('rec');
		$w->dataElement('count',$s151{$k});
		$w->dataElement('srcip',$k);
		$w->dataElement('fqdn',resolve($k));
		$w->dataElement('subdir', $s15{$l});
		$w->dataElement('status', $status2);
		$w->dataElement('url',$url2);
		$w->dataElement('fqdn',resolve($_[0]));
		$w->endTag('rec');
	    }
	}
    }
    $w->endTag('unsuc_subdir_ip');
        

    # List attempted form manipulation
    $xx = 1;
    sumhash (\%s16);
    $w->startTag('formmanip', 'total' => $sum, 'uniq' => $uniq);
    $w->dataElement('title', 'List suspected FORM manipulation');
    $w->dataElement('desc', '');
    foreach $k (sort {$s16{$b} <=> $s16{$a}} keys %s16)
    {
	@_ = split "�", $k;
	$w->startTag('rec');
	$w->dataElement('count',$s16{$k});
	$w->dataElement('query',$_[1]);
	$w->dataElement('srcip',$_[0]);
	$w->dataElement('fqdn',resolve($_[0]));
	$w->endTag('rec');
    }
    $w->endTag('formmanip');
    

    # List attempted Anonymous Proxy Scans
    $xx = 1;
    sumhash (\%s17);
    $w->startTag('locateproxy', 'total' => $sum, 'uniq' => $uniq);
    $w->dataElement('title', 'Attempts to locate Proxy');
    $w->dataElement('desc','This indicates attempts to locate and possibly use the site to stage further attacks. If the proxy attempts are successful, the site could be used to relay spam or participate in illegitimate activities.');

    foreach $k (sort {$s17{$b} <=> $s17{$a}} keys %s17)
    {
	@_ = split "�", $k;
	$w->startTag('rec');
	$w->dataElement('count', $s17{$k});
	$w->dataElement('status', $_[1]);
	$w->dataElement('url', $_[2]);
	$w->dataElement('srcip',$_[0]);
	$w->dataElement('fqdn',resolve($_[0]));
	$w->endTag('rec');
	if ($xx++ == $topmax) { last; }
    }
    $w->endTag('locateproxy');


    # List exceedingly Long URL's
    $xx = 1;
    sumhash (\%s18);
    $w->startTag('longurlattempt', 'total' => $sum, 'uniq' => $uniq);
    $w->dataElement('title', 'Exceedingly Long URLs');
    $w->dataElement('desc', "These could indicate attempts to locate and use Buffer Overflows to compromise the Web Server, and shoud be considererd as serious attempts to breach Security.");
    
    foreach $k (sort {$s18{$b} <=> $s18{$a}} keys %s18)
    {
	@_ = split "�", $k;
	$w->startTag('rec');
	$w->dataElement('count',$s18{$k});
	$w->dataElement('status',$_[3]);
	$w->dataElement('length',$_[2]);
	$w->dataElement('url',$_[0]);
	$w->dataElement('srcip',$_[1]);
	$w->dataElement('fqdn',resolve($_[1]));
	$w->endTag('rec');
	if ($xx++ == $topmax) { last; }
    }
    
    $w->endTag('longurlattempt');
    $w->endTag('report');
    $w->end();
    
    #close OUT;
    slog('Done printing XML Output');
}  # End sub printxml



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

} # End sub printstats


######################
# Below are various routines to ease things up

sub prntx () {
    my ($xmlname, $xmlvalue) = @_ ;
    $w->startTag($xmlname);
    $w->characters($xmlvalue);
    $w->endTag($xmlname);
} # End sub prntx

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
} # End sub sumhash

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
    syslog('info', '%s', @_);
    closelog;
}

sub plog {
    # Generate Debug Log
    my $txt = shift;
    #open DBG, ">>/tmp/secsrch.dbg";
    #print STDERR $txt;
    #close DBG;
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

sub sanitize {  # Sub to sanitize filenames and check for illegal characters
    my $x = shift;
    #print STDERR "$x\n";
    my $count = 0;
    if (($x =~ s/[`&'*?^()#$|\>\<\[\]\n\r]//g) gt 0) {
	#print STDERR "Error: $x\n";
	return 99;

    } else 
    {
	return 0;
    }
} 

# Function to print status to temp file, when run form CGI (upload.cgi)
 
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

sub printheaders {
    print "Analyzed log line:\n";
    print "$_\n";
    
    foreach $f (keys %logformat) {
	print "Identified Format: $f\n";
    }
    print "Client \$ip = $ip\n"; 
    print "\$serverip = $serverip\n";
    print "\$sitename = $sitename\n";
    print "\$status = $status\n";
    print "\$user = $user\n";
    print "\$date = $date\n";
    print "\$method = $method\n";
    print "\$url = $url\n";
    print "\$len = $len\n";
    print "\$referer = $referer\n";
    print "\$cookie = $cookie\n";
    print "\$uri = $uri\n";
    print "\$browser = $browser\n";
    print "\$httpver = $httpver\n";
    print "\$servername = $servername\n";
}

# And that's about all there is....
