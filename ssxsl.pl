#!/usr/bin/perl -W 

use XML::LibXSLT;
use XML::LibXML;

my $parser = XML::LibXML->new();
my $xslt = XML::LibXSLT->new();

my $source = $parser->parse_file($ARGV[0]);
#my $source = $parser->parse_file('/usr/local/apache/htdocs/xmltest.xml');
#my $style_doc = $parser->parse_file('xtextout.xsl');
#my $style_doc = $parser->parse_file('xhtmlout.xsl');
my $style_doc = $parser->parse_file($ARGV[1]);

my $stylesheet = $xslt->parse_stylesheet($style_doc);

my $results = $stylesheet->transform($source);

print $stylesheet->output_string($results);
