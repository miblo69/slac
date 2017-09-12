#!/usr/bin/perl
# $Header: /home/mibl/Dev/slac/RCS/mail_parse.pl,v 1.23 2004/08/13 10:40:29 mibl Exp mibl $
# Script to handle incoming mail messages, and forward them
# to the appropriate analysis tools. Reads mail-stream
# from standard input, and parses with MIME-Tools.
# Currently 'secsrch.pl' is the only tool it forwards to.
#
# 2002-05-15 Initial Development start
# 2002-05-15 
# 2002-06-10 Added support for PGP-decryption of logfiles
# 2002-06-11 Added support for ZIP file unpacking
# 2003-04-29 Added support for getting logformat from Subject
# 2004-08-13 Changed handling so that this program just 
#            parses the mails, and places each file in a directory.
#            The passing of each file to processing is handled by 
#            a seperate process.


#use Sys::Syslog;                          # all except setlogsock, or:
use Sys::Syslog qw(:DEFAULT setlogsock);  # default set, plus setlogsock

$DEBUG = 1;

slog("New Mail: mail_parse.pl Started " . localtime() . "\n");

#$parseoutputdir = '/tmp';

#$parseoutputdir = '/home/logger/';
$parseoutputdir = '/var/tmp';
$LOGGERDIR = 'logger';
$FWLOGGERDIR = 'fwlogger';
$ANALYSIS = '/usr/local/slac/secsrch.pl';
$FWANALYSIS = '/usr/local/slac/fw1-secsrch.pl';
$MAIL = '/bin/mail';
#$OPT = "-p -m ";  # Options to be passed to the ANALYSIS program
$OPT = "-p ";  # Options to be passed to the ANALYSIS program

$FWOPT = " -D -p ";   # Options for firewall analysis (Progress & No reverse dns)
our $subject;
$subject = '';

slog("ParseOutputDir: " . $parseoutputdir . "\n");

if ($DEBUG gt 1) {
    slog("Debug is on\n");
    $of = $parseoutputdir . '/' . "$$-mail.log";
    slog("Outfile: $of\n");
    open OUT, ">>$of";
    open IN, "<&STDIN";
    while (<IN>) {
	print OUT $_;
    }
    close OUT;
    close IN;
    slog("Debug is ON, so we exit after printing the mail to a file.\n");
    slog("Exited.\n");
    exit;
}

use MIME::Parser;
use Mail::Send;
use Archive::Zip;
my $parser = new MIME::Parser;	

if ($ENV{'OS'} =~ m/windows/i) {
    $os = 'win'; 		#Windows
    $osenv = 'OS';
    $parseoutputdir = '\temp';
}
elsif ($ENV{'OSTYPE'} =~ m/solaris/i) {
    $os = 'sol';		#Solaris
    $osenv = 'OSTYPE';
}
else {
    $os = 'unknown';
}

slog("\$parseoutputdir = $parseoutputdir\n");

$parser->output_under($parseoutputdir);
#$parser->output_dir($parseoutputdir);
#$parser->output_prefix("XXX");
slog("Have set outputdir\n");

$ent = $parser->parse(\*STDIN);

slog("Sett parser to STDIN\n");

dump_entity($ent) if $ent;

slog("Mail_Parse Done " . localtime() . "\n");

sub dump_entity {
    slog("Start dump_entity\n");
    my $ent = shift;
    my @parts = $ent->parts;
    $f = 0;   #Counter for number of files processed
    $authorized = 0;
    $single = 1;
    if (@parts) {  # multipart...
	$single = 0;
	slog("Multipart:\n");
        $to = $ent->head->get('To');
	if ($to =~ m/^fwlogger\@/) {
	    #$parseoutputdir = $parseoutputdir . '/' . $FWLOGGERDIR; 
	    slog("  Analyzing firewall log");
	    $ANALYSIS = $FWANALYSIS;
	    $OPT = $FWOPT;
	} else {
	    #$parseoutputdir = $parseoutputdir . '/' . $LOGGERDIR;
	    slog("  Analyzing Web log");
	}

	slog("  MP To: $to\n");
        $from = $ent->head->get('From');
	slog("  MP From: $from\n");
	$subject = $ent->head->get('Subject');
	#$subject = $subject;
	#print "Subj " . $subject;
	#$subject =~ s/\%/\%\%/g;
	#print "Subj2: $subj2\n";
        slog("Subject: ". $subject);

	$from =~ m/([\w\d\.]+\@[\w\d\.]+)/;

	$rep = $1;

	if (authorized($rep) eq -1) {
	    slog("$rep is unauthorized.\n");
	    $msg = new Mail::Send ;
	    $msg->subject('Not Authorized');
	    $msg->to($rep);
	
	    $FH = $msg->open;
	    #print $FH "You aint authorized man. Beat it.\n";
	    #print $FH "The address \'$rep\' just isn't good enough.\n";
	    print $FH "The address you used has not been authorized to use the SLAC service.\n";
	    print $FH "Send an e\-mail to mibl\@a51.mine.nu,\n";
	    print $FH "containing the address you want to use.\n";
	    print $FH "\n\n";
	    $FH->close;         # complete the message and send it
	
	    return -1;
	}

	$subject = $ent->head->get('Subject');
	#$subject =~ s/\%/\%\%/g;
	#print "got subj: " . $ent->head->get('Subject') . "\n";
	#print $subject;
	slog('SSSSubject: ' . $subject);
	$replyto = $ent->head->get('Reply-To');
	slog("" . localtime() . "\n");
        slog("From: $from  To: $to  Subject: " . $subject ." Reply\-To: $replyto\n");
        map { dump_entity($_) } @parts;

    } else {    # single part...
	slog("Single Part:\n");
	$part = scalar($ent->head->mime_type);
	$path = $ent->bodyhandle->path;
	if (-f $path) { slog("File successfully created: $path"); } 
	if (! defined $to) { $to = $ent->head->get('To'); }
	if (! defined $from ) {
	    $from = $ent->head->get('From');
	    $from =~ m/([\w\d\.]+\@[\w\d\.]+)/;
	    $rep = $1;
	}
	#slog($ent->head->get('Subject'));
	if (! defined $subject) { 
	    #print "Not deffed: " . $ent->head->get('Subject');
	    $subject = $ent->head->get('Subject'); 
	    slog("  Not def $subject");
	} else {
	    slog("  Def $subject");
	}
	slog("  SP From: $from\n");
	slog("  SP To: $to\n");
        slog("  SP Part: $path ($part)\n");
	slog("  SP Subject: $subject");
	$path =~ m/(.*?)\/([\d\w\.\-]+)$/;
	slog("\$1 $1\n");
	slog("\$2 $2\n");
	$dir = $1;
	if ($single eq 1) {
	    $file = $path;
	} else {
	    $file = $2;
	}
	slog("Analyzing $file ($part)\n");
	# If logfile; open it and start parsing...
	if (($part eq 'application/octet-stream') ||
	    ($part eq 'application/x-gzip') ||
	    ($part eq 'application/x-gzip-compressed') ||
	    ($part eq 'text/plain') ||
	    ($part eq 'application/zip')) 
	{
	    #Check if encrypted, before analyzing...
	    if (($path =~ m/\.pgp$/i) || 
		($path =~ m/\.asc$/i) || 
		($path =~ m/\.gpg/i)) {
		slog("Found PGP encrypted file $path");
		#$path =~m/(.*)\/(.*)/;
		#$rundir = $1;
		slog("Running Dir: $dir");
		$arg = 'HOME=/home/logger /usr/bin/gpg --batch -v ' . $path . ' 2>&1';
		# Remove extension, since new file is written to it by gpg.
		$path =~ m/(.+)\.(.+)/;
		$gpgoutfile = $1;
		slog("PGP Args: $arg\n");
		@res = `$arg`;
		slog("Exit message: $!\n");
		slog("Exit Code: " . ($?/256) ."\n");
		foreach $x (@res) {
		    slog("PGP Res:$x");
		    if ($x =~ m/file\sname\=\'(.*)\'/i) {
			$path = $dir . '/' . $1;
			slog("PGP Outfile: ". $path);
		    }
		}
		# If filename of gpg archive differs from oroginal filenam,
		# do a rename of the file
		if ($gpgoutfile ne $path) {
		    slog("Renaming from: $path, to $gpgoutfile");
		    rename $gpgoutfile,$path;
		}
	    }

	    
	    if ($path =~ m/(.*)\.zip$/i) {
		slog("Found Zip file... $path\n");
		# Check if Zip. Then UnZip and 
		$zip = Archive::Zip->new();
		die 'read error' unless $zip->read($path) == AZ_OK;
		my @member = $zip->memberNames();
		print $zip->numberOfMembers();
		
		foreach $x (@member) {
		    #print "$x\n";

		    #$zip->extractMember($x, $parseoutputdir . '/' . $x);
		    $zip->extractMember($x, $dir . '/' . $x);
		    #$path = $parseoutputdir . '/' . $x;
		    $path = $dir . '/' . $x;
		    slog("Found $x. Extracted to $path");
		    #analyze();
		}
	    }
	    else
	    {
		#analyze();
	    }
	}
    }
}

sub authorized {
    return 0;
    # Check if $rep is authorized for this..
    my $name = pop;
    open DB, '</usr/local/var/SAC_client';
    slog("From: $name\n");
    while (<DB>) {
        chomp;
        slog("  Looking: $_ \n");
        if ($_ eq $name) {
           slog("  Matched: $_\n");
	   
           $authorized = 1;
	   close DB;
	   return 0;
           last;
        }
    }
    close DB;
    return -1;

}

sub analyze {
    slog("Starting sub analyze\n");
    $maint = '/etc/SLACmaintenance';
    # Check if in maintenance Mode...
    if (-f $maint) {
	slog("SLAC in Maintenance\n");
	$arg = '/bin/cat ' . "$maint" . " | $MAIL -s \'Service Temporarily Down\' $rep\n";
	slog("Mail sent \($arg\)\n");
	print LOG "Executing \'$arg\' \n";
	@res = system($arg);

    } else { 
        # Not in maintenance
	# Call the external program to perform the analysis
	# No, no, no. Not any more. Simply place the file in a 
	# directory for later processing.

	$f++;
	$path =~ m/(.*)\/(.*)/;
	$dir = $1;               # Get Directory
	$filename = $2;          # Get Filename 
	$infile = $path;
	$outfile = $path . '.out';
	slog("Dir: $dir File: $filename\n");

	#$arg = "$ANALYSIS " . $OPT . " -C \'$subject\' $infile $outfile";
	#$arg = "$ANALYSIS " . $OPT . " $infile $outfile";
	if ($to =~ m/fwlogger\@/) {
	    $arg = "$FWANALYSIS " . $FWOPT . " \-i $infile \> $outfile";
	}
	slog("Creating Outfile with: \'$arg\'\n");
	#@res = system($arg);
	if (system($arg) == 0) {
	    slog("Mailing outfile\n");
	    $arg = "/bin/cat $outfile | $MAIL -s \'Results from $filename\' $rep ";
	    slog("Calling $MAIL \($arg\)\n");
	    #@res = system($arg);
	    print LOG "Executing \'$arg\' \n";
	    @res = system($arg);
	} else {
	    slog("Secsrch returned with errorcode $?\n");
	    #$arg = "$MAIL -s \'Error \- No Analysis\' $rep";
	}

    }
    #print LOG "Executing \'$arg\' \n";
    #@res = system($arg); 
}


#$ent->dump_skeleton;

#open OUT, ">&STDOUT";
#open MAIL, ">>/tmp/mail_$$.log";
#binmode OUT;
#print OUT localtime() . " Processing mail!\n";

#while (<IN>) {
#    print MAIL $_;
#    if (m/filename=\"(.*?)\"/) {
#	$file = 1;
#	open OUT, ">\/tmp\/$1";
#	next;
#    }
#    if ($file == 1) {
#	#print OUT decode_base64($_);
#    }
#}

 
# Add Syslog facility
sub slog {
    my $msg = shift @_;
    setlogsock('unix');
    openlog('mail_parse.pl', 'cons,pid', 'local2');
    syslog('info', '%s', $msg);
    closelog;
    return 0;
}
 
# And that's about all there is....
