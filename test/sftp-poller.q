#!/usr/bin/env qore
# -*- mode: qore; indent-tabs-mode: nil -*-

%require-our
%requires qore >= 0.8.9
%requires ssh2 >= 1.0
%requires SftpPoller >= 1.0

const Timeout = 10s;

const opts = (
    "privkey": "k,private-key=s",
    "mask": "m,mask=s",
    "help": "h,help"
    );

class MySftpPoller inherits SftpPoller {
    constructor(SFTPClient $sc, hash $opts) : SftpPoller($sc, $opts) {
    }

    nothing singleFileEvent(hash $fh) {
        printf("GOT FILE: %y\n", $fh - "data" + ("data_type": $fh.data.type(), "data_size": $fh.data.size()));
        # in this case, the polling stop operation will take effect after all the singleFileEvent() calls are made for the polling operation
        $.stopNoWait();
    }

    nothing postSingleFileEvent(hash $fh) {}
}

sub main() {
    my GetOpt $g(opts);
    my hash $o = $g.parse2(\$ARGV);

    my *string $url = shift $ARGV;
    if (!exists $url || $o.help || $o.iters < 0 || $o.threads < 0) {
	printf("usage: %s <url>
  url examples: sftp://user:password@host
 -k,--private-key=ARG  set private key to use for authentication
 -h,--help             for this help test\n", get_script_name(), Timeout / 1000);
	exit(1);
    }

    printf("using libssh2 version: %s\n", SSH2::Version);

    my hash $urlh = parse_url($url);

    my SFTPClient $sc($url);
    if ($o.privkey)
        $sc.setKeys($o.privkey);

    my code $info = sub (string $msg) { printf("INFO: %s\n", $msg); };
    my code $detail = sub (string $msg) { printf("DETAIL: %s\n", $msg); };
    my code $debug = sub (string $msg) { printf("DEBUG: %s\n", $msg); };

    my hash $opts = (
        "log_info": $info,
        "log_detail": $detail,
        "log_debug": $debug,
        );

    if ($urlh.path)
        $opts += ("path": $urlh.path);

    if ($o.mask)
        $opts += ("mask": $o.mask);

    my MySftpPoller $poller($sc, $opts);
    $poller.start();
    $poller.waitStop();
}

main();
