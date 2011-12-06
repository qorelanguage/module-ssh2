#!/usr/bin/env qore
# -*- mode: qore; indent-tabs-mode: nil -*-

# here we add fallback paths to the QORE_INCLUDE_DIR search path,
# in case QORE_INCLUDE_DIR is not set properly
%append-include-path /var/opt/qorus/qlib:$OMQ_DIR/qlib:/opt/qorus/qlib

%include qorus-client.ql
#/

%require-our
%strict-args
%no-child-restrictions

%exec-class filter

const opts =
    ( "post"    : "post,p",
      "tex"     : "posttex,x",          # use TeX syntax for "post" processing
      "links"   : "links,l",
      "svc"     : "service,s",
      "ssvc"    : "system-services=s",
      "sidx"    : "service-index",
      "help"    : "help,h"
    );

class DocumentTableHelper {
    private {
        bool $.css = False;
        bool $.inTable = False;
    }

    public {}

    process(string $line) returns string {
        if ($line =~ /@page/) {
            #printf("PAGE: css: %n %s", $.css, $line);#exit(1);
            $.css = False;
        }
        #printf("XXX %s", $line);

        if ($line !~ /^(\s)*\|/) {
            if ($.inTable) {
                $.inTable = False;
                return "    </table>\n" + $line;
            }
            return $line;
        }

        my string $str;

        if (!$.inTable) {
            if (!$.css) {
                $str = "    @htmlonly <style><!-- td.qore { background-color: #5b9409; color: white; } --></style> @endhtmlonly\n";
                $.css = True;
            }
            $str += "    <table>\n";
        }

	$.inTable = True;

	$str += "      <tr>\n";

	trim $line;
	splice $line, 0, 1;
	foreach my *string $cell in (split("|", $line)) {
	    trim $cell;
	    my *string $cs;
	    if ($cell =~ /^!/)
		$str += sprintf("        <td class=\"qore\"><b>%s</b></td>\n", substr($cell, 1));
	    else
		$str += sprintf("        <td>%s</td>\n", $cell);
	}	
	$str += "      </tr>\n";
	return $str;
    }
}

class filter {
    private {
	bool $.post;
	bool $.links;
	bool $.svc;
	bool $.help;
	hash $.o;
	*string $.sname;
	*string $.psname;
        string $.build;
        string $.qorever;
    }
    public {}

    constructor() {
	my GetOpt $g(opts);
	try {
	    $.o = $g.parse2(\$ARGV);
	}
	catch ($ex) {
	    printf("%s\n", $ex.desc);
	    exit(1);
	}
	if ($.o.help)
	    filter::usage();

	while (exists (my *string $fn = shift $ARGV)) {
	    my *list $fl = glob($fn);
	    foreach my string $fn in (exists $fl ? $fl : $fn) {
		if ($.o.post)
		    $.postProcess($fn);
		else if ($.o.tex)
		    $.postProcess($fn, True);
		else if ($.o.links)
		    $.processLinks($fn);
		else if ($.o.svc)
		    $.processService($fn);
		else if ($.o.sidx)
		    $.processServiceIndex($fn);
		else
		    $.process($fn);
	    }
	}
    }

    static usage() {
      printf("usage: %s [options] <file1> ...
  -p,--post                 post process files
  -l,--links                process API links only
  -s,--service              process Qorus service file (*.qsd)
     --system-services=ARG  give list of system services
     --service-index=ARG    create service index (requires --system-services)
  -q,--qore                 process Qore source file
  -h,--help                 this help text
", get_script_name());
      exit(1);
    }

    processServiceIndex(string $ifn) {
	if (!strlen($.o.ssvc))
	    throw "ERROR", "--system-services not specified";

	my File $if();
	$if.open2($ifn);

	my string $ofn = regex_subst($ifn, ".tmpl", "");

	printf("creating service index in %n\n", $ifn);

	my File $of();
	$of.open2($ofn, O_CREAT | O_WRONLY | O_TRUNC);

	my list $l = split(" ", $.o.ssvc);
	my hash $h;
	
	foreach my string $sfn in ($l) {
	    my File $sf();
	    $sf.open2($sfn);
	    my string $str = $sf.read(-1);
	    splice $str, 0, index($str, "@file");
            #printf("sfn=%n\n", $sfn);
	    $str = ($str =~ x/^@file [-a-z\.0-9]+ @brief (.*)/i)[0];
	    #printf("2 %s: %n\n", $sfn, $desc); exit(1); 
	    $h.$sfn = $str;
	}
	#printf("l=%n\n", $l);exit(1);

	while (exists (my *string $line = $if.readLine())) {
	    if ($line =~ /SERVICE_LIST/) {
		foreach my string $fn in (sort(keys $h)) {
		    my string $sn = $fn;
		    $sn =~ s/-v.+//g;
		    $of.printf("    - @link %s system.%s@endlink: %s\n", $fn, $sn, $h.$fn);
		}
		continue;
	    }

	    $of.print($line);
	}
    }

    processLinks(string $ifn, *File $of) {
	# service lookup hash
	my hash $sh;
	if (exists $.o.ssvc) {
	    foreach my string $svc in (split(" ", $.o.ssvc)) {
		my string $sn = $svc =~ x/([-a-z]+)-v/[0];
		$sh.$sn = $svc;
	    }
	    #printf("sh=%n\n", $sh);exit(1);
	}

	my File $if();
	$if.open2($ifn);

	my string $ofn = regex_subst($ifn, ".tmpl", "");

	printf("processing %n for API links\n", $ifn);

        if (!exists $of) {
            $of = new File();
            $of.open2($ofn, O_CREAT | O_WRONLY | O_TRUNC);
        }

	my DocumentTableHelper $dth();

	while (exists (my *string $line = $if.readLine())) {
	    filter::fixAPIRef(\$line);
	    $line = $dth.process($line);
	    
	    while (exists (my *string $svc = ($line =~ x/(##[-a-z]+)/[0]))) {
		my string $orig = $svc;
		splice $svc, 0, 2;
		if (!exists $sh.$svc)
		    throw "ERROR", sprintf("unknown service: %s (%n)", $svc, $orig);
		$line = replace($line, $orig, $sh.$svc);
                #printf("fixed %N -> %N\n", $orig, $sh.$svc);
	    }

            if (exists (my *string $inc = $line =~ x/^#include "(.*)"\s*$/[0])) {
                $.processLinks($inc, $of);
                continue;
            }
	    
            if ($line =~ /{qore_version}/)
                $line = regex_subst($line, "{qore_version}", $.getQoreVersion(), RE_Global);

	    $of.print($line);
	}
    }

    private getBuild() {
        if (!exists $.build) {
            $.build = `svnversion|sed s/M//|sed s/:.*//`;
            trim $.build;
        }
        return $.build;
    }

    private getQoreVersion() {
        if (!exists $.qorever)
            $.qorever = sprintf("%d.%d.%d", Qore::VersionMajor, Qore::VersionMinor, Qore::VersionSub);
        return $.qorever;
    }

    processService(string $ifn) {
	my File $if();
	$if.open2($ifn);

	my string $ofn = shift $ARGV; #basename($ifn);

	printf("processing service file: %n -> %n\n", $ifn, $ofn);

	my File $of();
	$of.open2($ofn, O_CREAT | O_WRONLY | O_TRUNC);

	# get header information about the service
	$.getServiceInfo($if, $of, $ofn);	

	my *string $name;
	my *string $desc;
	my *string $comment;
	my *bool $intern;
	my *bool $write;
	my *string $lock;

	# header output flag
	my bool $ho = False;

	while (exists (my *string $line = $if.readLine())) {
	    # get method name
	    if (!exists $name && exists ($name = ($line =~ x/#[ ]*name:(.*)$/)[0])) {
		trim $name;
		#$of.printf("//! @fn %s()\n", $name);
		continue;
	    }

	    # process all system API references
	    filter::fixAPIRef(\$line);

	    # get method description
	    if (!exists $desc && exists ($desc = ($line =~ x/#[ ]*desc:(.*)$/)[0])) {
		trim $desc;
		#$of.printf("//! @brief %s\n", $desc);
		continue;
	    }

            if (exists (my $desc1 = ($line =~ x/#! (.*)$/)[0])) {
		trim $desc1;
                $desc = $desc1;
                #printf("got: %s\n", $desc);
		continue;
            }

	    # check for write flag
	    if (!exists $write && exists (my *string $str = ($line =~ x/#[ ]*write:(.*)$/)[0])) {
		trim $str;
		$write = parseBoolean($str);
	    }

	    # check for intern flag
	    if (!exists $intern && exists (my *string $str = ($line =~ x/#[ ]*intern:(.*)$/)[0])) {
		trim $str;
		$write = parseBoolean($str);
	    }

	    # check for lock flag
	    if (!exists $lock && exists ($lock = ($line =~ x/#[ ]*lock:(.*)$/)[0])) {
		trim $lock;
	    }

	    if ($line =~ /\/\*\*/) {
		$comment = $.getComment($line, $if, $of, True);
		# remove end comment marker
		$comment =~ s/\*\///;
		splice $comment, -1;
		continue;
	    }

	    if ($line =~ /sub [a-z_0-9]+/) {
		my string $sn = ($line =~ x/sub ([a-z_0-9]+)\(/i)[0];
		#if (!exists $sn) { printf("line=%n\n", $line); exit(1);}
		if (!exists $name)
		    $name = $sn;

		if ($name == $sn) {
		    $line = replace($line, "sub " + $name, "sub " + $.psname + "__4_" + $name);

		    $line =~ s/sub //;
		    $line =~ s/\*/__3_/g;
		    $line =~ s/\$/__6_/g;
		    if (exists (my *list $x = ($line =~ x/(.*\)) *returns (\*?[a-zA-Z0-9_]+)/))) {
			#printf("x=%n\n", $x);
			$line = $x[1] + " " + $x[0] + $x[2];
		    }
		    else {
			$line =~ s/[ ]*{[ ]*$//;
			chomp $line;
		    }

		    if (exists $desc) {
			$of.printf("//! %s\n", $desc);
			$of.printf("%s", strlen($comment) ? $comment : "/**\n");
			if (exists $lock && $lock != "none")
			    $of.printf("   @note - \\c lock: @ref OMQ::SL%s\n", $lock == "write" ? "Write" : "Read");
			if ($intern)
			    $of.printf("   @note - \\c intern: \\c True (can only be called internally)\n");
			if ($write)
			    $of.printf("   @note - \\c write: \\c True (external calls require @ref OMQ::QR_CALL_SYSTEM_SERVICES_RW)\n");
			$of.print("*/\n");
			$ho = True;
		    }
		    $of.printf("%s {}\n\n", $line);

                    delete $desc;
                    delete $comment;
		}
		continue;
	    }

	    if ($line =~ /#[ ]*END/) {
		delete $desc;
		delete $name;
		delete $comment;
		delete $lock;
		delete $intern;
		delete $write;
		$ho = False;
	    }

	    #$line =~ s/\#/\/\//;
	    
	    #$of.print($line);
	}
    }

    postProcess(string $ifn, bool $tex = False) {
	my File $if();
	$if.open2($ifn);

	my string $ofn = $ifn + ".new";

	printf("processing API file %s\n", $ifn);

	my File $of();
	$of.open2($ofn, O_CREAT | O_WRONLY | O_TRUNC);

	on_success rename($ofn, $ifn);

	while (exists (my *string $line = $if.readLine())) {
            if ($tex) {
                $line =~ s/\\_\\-\\_\\-1\\_\\-/[/g;
                $line =~ s/\\_\\-\\_\\-2\\_\\-/]/g;
                $line =~ s/\\_\\-\\_\\-3\\_\\-/*/g;
                $line =~ s/\\_\\-\\_\\-4\\_\\-/./g;
                $line =~ s/\\_\\-\\_\\-5\\_\\-/-/g;
                $line =~ s/\\_\\-\\_\\-6\\_\\-/\$/g;
            } 
	    $line =~ s/__1_/[/g;
	    $line =~ s/__2_/]/g;
	    $line =~ s/__3_/*/g;
	    $line =~ s/__4_/./g;
	    $line =~ s/__5_/-/g;
	    $line =~ s/__6_/$/g;

	    # remove "inline" tags
	    $line =~ s/\[inline\]//g;
	    $line =~ s/, inline\]/]/g;
	    $line =~ s/\[inline, /[/g;

	    if (exists (my *string $api = ($line =~ x/(omq_[us][a-z_]+)/[0]))) {
		my string $mapi = $api;
		$line = regex_subst($line, $mapi, $api);
	    }

	    $of.print($line);
	}
    }

    process(string $ifn) {
	my File $if();
	$if.open2($ifn);

	my string $ofn = basename($ifn);

	printf("processing API file %s -> %s\n", $ifn, $ofn);

	my File $of();
	$of.open2($ofn, O_CREAT | O_WRONLY | O_TRUNC);

	my string $comment = "";
	my *string $api;
	while (exists (my *string $line = $if.readLine())) {
	    if ($line =~ /#!/) {
		$line =~ s/#!/\/\/!/;
		if ($line =~ /@file/) {
		    $of.print($line + "\n");
		    continue;
		}
		$comment = $.getComment($line, $if, $of);
		continue;
	    }
	    if (strlen($comment) && !exists $api && (exists ($api = ($line =~ x/\"(omq\.[-a-z\.\[\]]+)\"/[0])))) {
		#printf("api=%s()\n", $api);
		continue;
	    }
	    if (strlen($comment) && exists $api && (exists (my $args = ($line =~ x/\"code\"[^(]*\((.*)\) returns/[0])))) {
		$args =~ s/hash \$[a-z_]+(,( )?)?//;
		$args =~ s/\*/__3_/g;
		$args =~ s/\$/__6_/g;
		#printf("args=%s\n", $args);
		my string $orig_api = $api;
		$orig_api =~ s/[\.-]/_/g;
		$orig_api =~ s/_\[.+//g;
		
		my *string $rv = ($line =~ x/returns ([^{]*)/)[0];
		if (exists $rv)
		    $rv =~ s/\*/__3_/g; #/

		$of.printf("/** @anchor %s */\n\n", $orig_api);
		$of.print($comment);
		filter::fixAPI(\$api);
		$of.printf("%s%s(%s) {}\n\n", $rv, $api, $args);
		$comment = "";
		delete $api;
	    }
	}
    }

    getServiceInfo(File $if, File $of, string $ofn) {
	my string $st;
	my string $sn;
	my *string $desc;
	my *string $comment;

	while (exists (my *string $line = $if.readLine())) {
	    # check for service type
	    if (exists (my *string $temp = ($line =~ x/#[ ]*servicetype:(.*)$/)[0])) {
		trim $temp;
		$st = tolower($temp);
		continue;
	    }

	    # check for service name
	    if (exists (my *string $temp = ($line =~ x/#[ ]*service:(.*)$/)[0])) {
		trim $temp;
		$sn = $temp;
		continue;
	    }

	    # check for service description and change it to file description
	    if (!exists $desc && exists ($desc = ($line =~ x/#[ ]*servicedesc:(.*)$/)[0])) {
		trim $desc;
	    }
	    else if (!exists $comment && $line =~ /\/\*\*/) { #/){
		$comment = $.getComment($line, $if, $of);
		$comment =~ s/^\/\*\*//g; #/;
		continue;
	    }
	    else if ($line =~ /ENDSERVICE/) {
	    	$of.printf("//! @anchor %s\n", $sn);
	    	break;
	    }
	}
	$.sname = $sn;
	$.psname = $.sname;
	$.psname =~ s/-/__5_/g;

	if (exists $comment) {
	    $of.printf("/** @file \"%s\" @brief %s\n", $ofn, $desc);
	    $of.printf("    @file \"%s\" @details %s", $ofn, $comment);
	}
	else
	    $of.printf("//! @file \"%s\" @brief %s\n", $ofn, $desc);

	$of.print("\n");
    }

    static string fixAPI(any $api) {
	$api =~ s/\./__4_/g;
	$api =~ s/-/__5_/g;
	$api =~ s/\[/__1_/g;
	$api =~ s/\]/__2_/g;
	return $api;
    }

    static fixAPIRef(reference $line) {
	while (exists (my *string $api = ($line =~ x/((omq|arch|datasource|info|omqmap|prop|queue|status|tibco|tibrv-api-gateway)\.[-a-zA-Z0-9_\.\[\]]+)\(/)[0])) {
	    my string $na = filter::fixAPI($api);
	    $line = replace($line, $api + "(", $na + "(");
            #printf("replace %n -> %n\n", $api, $na);
	}

	$line =~ s/\$\.//g;
	$line =~ s/\$/__6_/g;
    }

    fixParam(reference $line) {
	if ($line =~ /@param/) {
	    $line =~ s/([^\/\*])\*/$1__3_/g;
	    $line =~ s/\$/__6_/g;
	}
	if (exists (my *string $str = regex_extract($line, "(" + $.sname + "\\.[a-z0-9_]+)", RE_Caseless)[0])) {
	    my string $nstr = $str;
	    #printf("str=%n nstr=%n\n", $str, $nstr);
	    $nstr =~ s/\./__4_/g;
	    $line = replace($line, $str, $nstr);
	}
    }

    getComment(string $comment, File $if, File $of, bool $fix_param = False) {
	$comment =~ s/^[ \t]+//g;
	if ($fix_param)
	    $.fixParam(\$comment);
        
	while (exists (my *string $line = $if.readLine())) {
	    $line =~ s/^[ \t]+//g;
	    $line =~ s/\$/__6_/g;
            
	    if ($fix_param)
		$.fixParam(\$line);
            
	    filter::fixAPIRef(\$line);
            
	    if ($line =~ /\*\//) {
		$comment += $line;
		break;
	    }
	    if ($line =~ /\/\*/) #/)
		$comment += $line;
            else
                $comment += "   " + $line;
        }
	#printf("comment: %s", $comment);
	return $comment;
    }

}
