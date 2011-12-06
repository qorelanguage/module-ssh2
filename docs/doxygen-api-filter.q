#!/usr/bin/env qore
# -*- mode: qore; indent-tabs-mode: nil -*-

%requires qore >= 0.8.1

%require-our
%strict-args

%exec-class filter

const opts =
    ( "post"    : "post,p",
      "tex"     : "posttex,x",          # use TeX syntax for post processing
      "links"   : "links,l",
      "qore"    : "qore,q",
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
                else if ($.o.qore)
                    $.processQore($fn);
		else
		    $.process($fn);
	    }
	}
    }

    static usage() {
      printf("usage: %s [options] <file1> ...
  -p,--post                 post process files
  -l,--links                process API links only
  -h,--help                 this help text
", get_script_name());
      exit(1);
    }

    processLinks(string $ifn, *File $of) {
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

    postProcess(string $ifn, bool $tex=False) {
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

	    if (exists (my $api = ($line =~ x/(omq_[us][a-z_]+)/[0]))) {
		my $mapi = $api;
		$line = regex_subst($line, $mapi, $api);
	    }

	    $of.print($line);
	}
    }

    process(string $ifn) {
	my File $if();
	$if.open2($ifn);

	my string $ofn = shift $ARGV;

	printf("processing API file %s -> %s\n", $ifn, $ofn);

	my File $of();
	$of.open2($ofn, O_CREAT | O_WRONLY | O_TRUNC);

	my string $comment = "";
	my *string $api;
	while (exists (my *string $line = $if.readLine())) {
	    if ($line =~ /\/\/!/) {
		if ($line =~ /@file/) {
		    $of.print($line + "\n");
		    continue;
		}
                my bool $continue;
                $comment = $.getComment($line, $if, \$continue);
                if ($continue) {
                    my *string $sig = $if.readLine();
                    if ($sig =~ /\/\*\*#/) {
                        $sig = $.getCodeComment($sig, $if);
                    }
                    else if ($sig !~ /^\/\/#/) {
                        printf("ERROR: signature line has wrong format: %n\n", $sig);
                        exit(1);
                    }
                    else {
                        splice $sig, 0, 4;
                        $sig =~ s/\$/__6_/g;
                    }
                    $of.printf("%s%s\n", $comment, $sig);
                }
                else
                    $of.printf("%s\n", $comment);
		continue;
	    }
            if ($line =~ /\/\*\*#/) {
                $comment = $.getCodeComment($line, $if);
                $of.printf("%s\n", $comment);
                continue;
            }
        }
    }

    string getCodeComment(string $comment, File $if) {
	$comment =~ s/\/\*\*\#//g;

	while (exists (my *string $line = $if.readLine())) {
	    $line =~ s/^[ \t]+//g;
	    $line =~ s/\$/__6_/g;

	    if ($line =~ /\*\//) {
                $line =~ s/\*\///;
		$comment += $line;
		break;
	    }
            $comment += $line;
	}
	#printf("comment: %s", $comment);
	return $comment;        
    }

    static fixAPI(any $api) returns string {
	$api =~ s/\./__4_/g;
	$api =~ s/-/__5_/g;
	$api =~ s/\[/__1_/g;
	$api =~ s/\]/__2_/g;
	return $api;
    }

    static fixAPIRef(reference $line) {
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

    string getComment(string $comment, File $if, reference $continue) {
	$comment =~ s/^[ \t]+//g;

	my DocumentTableHelper $dth();

        my bool $first = True;
	while (exists (my *string $line = $if.readLine())) {
            if ($first) {
                $first = False;
                if ($line =~ /^\/\*\*#/) {
                    $continue = False;
                    return $.getCodeComment($comment + $line, $if);
                }
                $continue = True;
            }

	    $line =~ s/^[ \t]+//g;
	    $line =~ s/\$/__6_/g;

            filter::fixAPIRef(\$line);

	    $line = $dth.process($line);

	    if ($line =~ /\*\//) {
		$comment += $line;
		break;
	    }
	    if ($line =~ /\/\*/)
		$comment += $line;
	    else
		$comment += "   " + $line;
	}
	#printf("comment: %s", $comment);
	return $comment;
    }

    processQore(string $fn) {
	my File $if();
	$if.open2($fn);

	$fn = basename($fn);
	my int $i = rindex($fn, ".");
	if ($i == -1) {
	    stderr.printf("%s: no extension; skipping\n", $fn);
	    return;
	}

	my string $nn = $fn;

	my File $of();
	$of.open2($nn, O_CREAT|O_WRONLY|O_TRUNC);

	my $class_name;
	my $ns_name;

	# class member private flag
	my bool $pp;

	# method private flag
	my bool $mpp;

	# method private count
	my int $mpc = 0;

	# class bracket count
	my int $cbc = 0;

	# namespace bracket count
	my int $nbc = 0;

	my bool $in_doc = False;

	while (exists (my *string $line = $if.readLine())) {
	    # skip parse commands
	    if ($line =~ /^%/)
		continue;

            $line =~ s/\$\.//g;
	    $line =~ s/([^\/\*])\*([a-zA-Z])/$1__3_$2/g;
            $line =~ s/\$/__6_/g;

	    filter::fixAPIRef(\$line);

	    if ($in_doc) {
		if ($line =~ /\*\//)
		    $in_doc = False;
		$of.print($line);
		continue;
	    }

	    if ($line =~ /\/\*\*/) {
		if ($line !~ /\*\/$/)
		    $in_doc = True;
		$of.print($line);
		continue;
	    }

	    $line =~ s/\$\.//g;
	    #$line =~ s/\$//g;
	    $line =~ s/\#/\/\//;
	    $line =~ s/our /extern /g;
	    $line =~ s/my //g;
	    $line =~ s/sub //;

	    my any $x;

	    # convert class inheritance lists to c++-style declarations
	    if ($line =~ /inherits / && $line !~ /\/(\/|\*)/) {
		trim $line;
		$x = ($line =~ x/(.*) inherits ([^{]+)(.*)/);
		$x[1] = split(",",$x[1]);		
		foreach my $e in (\$x[1]) {
		    if ($e !~ /(private|public)]/)
			$e = "public " + $e;
		}
		trim($x[0]);
		$line = $x[0] + ":" + join(",", $x[1]) + $x[2] + "\n";
		#printf("x=%n line=%s\n", $x, $line);
		#$of.print($line);
		#continue;
	    }

	    $x = ($line =~ x/^namespace (\w+(::\w+)?)/)[0];
	    if (strlen($x)) {
		#printf("namespace %n\n", $x);
		$ns_name = $x;

		if ($nbc != 0)
		    throw "ERROR", sprintf("namespace found but nbc=%d\nline=%n\n", $cbc, $line);

		if ($line =~ /{/ && $line !~ /}/)
		    ++$nbc;
		    
		$of.print($line);
		continue;
	    }
	    else {
		$x = ($line =~ x/^class (\w+(::\w+)?)/)[0];
		if (strlen($x)) {
		    #printf("class %n\n", $x);
		    $class_name = $x;

		    if ($cbc != 0)
			throw "ERROR", sprintf("class found but cbc=%d\nline=%n\n", $cbc, $line);

		    if ($line =~ /{/ && $line !~ /}/) {
			$line += "\npublic:\n";
			++$cbc;
		    }
		    
		    $of.print($line);
		    continue;
		}
		else if (exists $class_name) {
		    if ($line =~ /{/) {
			if ($line !~ /}/)
			    ++$cbc;
		    }
		    else if ($line =~ /}/) {
			--$cbc;
			if (!$cbc) {
			    trim $line;
			    $line += ";\n";
			    delete $class_name;
			}
		    }
		    
		    if (exists ($x = ($line =~ x/(public|private)[ \t]+{(.*)}/)[1])) {
			$of.printf("private:\n%s\npublic:\n", $x);
			continue;
		    }
		    else if ($line =~ /(public|private) *{/) {
			$line =~ s/{/:/;
			#printf("line: %s\n", $line);
			$pp = True;
		    }
		    else if ($pp && $line =~ /}/) {
			$line = "public:\n";
			$pp = False;
		    }
		}
		else if (exists $ns_name) {
		    if ($line =~ /{/) {
			if ($line !~ /}/)
			    ++$nbc;
		    }
		    else if ($line =~ /}/) {
			--$nbc;
			if (!$nbc) {
			    trim $line;
			    $line += ";\n";
			    delete $ns_name;
			}
		    }
		}
	    }
	    
	    if (!$pp && $line !~ /^[ \t]*\/\//) {
		my list $mods = ();
		if ($line !~ /"/)
		    while (exists (my *list $l = ($line =~ x/(.*)(synchronized|private[^-:]|public[^-:]|static)(.*)/))) {
			$mods += $l[1];
			$line = $l[0] + $l[2];
		    }

		if (elements $mods) {
		    trim $mods;
		    #printf("mods=%n line=%n\n",$mods, $line);
		    foreach my string $mod in ($mods) {
			if ($mod == "private") {
			    $mpp = True;
			    $of.printf("private:\n");
			}
			#$line = regex_subst($line, $mod, "");
		    }
		    #$mods = select $mods, $1 != "private" && $1 != "public";
		    #$line = join(" ", $mods) + $line;
		}

		$x = ($line =~ x/(.*\)) *returns (\*?[a-zA-Z_0-9]+)(.*)/);
		if (strlen($x[1])) {
		    #printf("x=%n\n", $x);
		    $line = $x[1] + " " + $x[0] + $x[2] + "\n";
		}

		if (exists $mods)
		    $line = join(" ", $mods) + " " + $line;
	    }

	    $of.print($line);

	    if ($mpp) {
		if ($line =~ /{/)
		    ++$mpc;
		else if ($line =~ /}/)
		    --$mpc;

		if (!$mpc) {
		    $of.print("public:\n");
		    $mpp = False;
		}
	    }
	}
    }
}
