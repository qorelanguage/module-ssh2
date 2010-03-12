#!/usr/bin/env qore
# -*- mode: qore; indent-tabs-mode: nil -*-

%require-our
%requires qore >= 0.7
%requires ssh2

sub ssh_test($url) {
    my $sc = new SSH2Client($url);

    $sc.connect();
    stdout.printf("%N\n", $sc.info());

    # test SSHClient::scpPut()
    my $chan = $sc.scpPut("test.txt", 5, 0664, 1982-01-05, 2010-02-01);
    $chan.write("hello");
    $chan.close();

    my $info;
    $chan = $sc.scpGet("test.txt", -1, \$info);
    stdout.printf("file info: %N\n", $info);
    my $str = $chan.read(0, -1);
    stdout.printf("file contents: %n\n", $str);

    $chan = $sc.openSessionChannel();
    #$chan.requestX11Forwarding();
    $chan.exec("ls -l");
    stdout.printf("%s", $chan.read());
    $chan.sendEof();
    $chan.close();
    stdout.printf("exit status: %d\n", $chan.getExitStatus());

    $chan = $sc.openSessionChannel();
    #$chan.setenv("TEST", "123");
    $chan.requestPty("vt100");
    $chan.shell();
    do {
	$str = $chan.read();
	stdout.printf("%s", $str);
	stdout.sync();
    } while ($str !~ /[\#\$\>] *$/);
    $chan.write("rm test.txt\n");
    do {
	$str = $chan.read();
	stdout.printf("%s", $str);
	stdout.sync();
    } while ($str !~ /[\#\$\>] *$/);
    $chan.write("ls -l\n");
    do {
	$str = $chan.read();
	stdout.printf("%s", $str);
	stdout.sync();
    } while ($str !~ /[\#\$\>] *$/);
    $chan.sendEof();
    $chan.close();
    #$chan.waitEof();
    #$chan.waitClosed();
    stdout.printf("exit\nexit status: %d\n", $chan.getExitStatus());
}

sub sftp_test($url) {
    my $sc = new SFTPClient($url);
    $sc.connect();
    printf("%N\n", $sc.info());
    my $c = new Counter(1);
    my $test = sub($c, $sc) { 
	$c.waitForZero();
	printf("%n\n", $sc.list());
    };
    for (my $i = 0; $i < 2; ++$i)
	background $test($c, $sc);

    $c.dec();
}

sub main() {
    my $url = shift $ARGV;
    if (!exists $url) {
	printf("usage: %s <url>\nurl example: ssh://user:password@host\n", get_script_name());
	exit(1);
    }
    printf("libssh2 version: %s\n", SSH2::Version);

    if ($url =~ /^sftp/)
	sftp_test($url);
    else
	ssh_test($url);
}

main();
