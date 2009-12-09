#!/bin/sh
# see if we need libtoolize or glibtoolize
if [ -x "`which libtoolize`" ] ; then
   lcmd=libtoolize
fi
if [ -x "`which glibtoolize`" ] ; then
   lcmd=glibtoolize
fi

if [ -z "$lcmd" ]; then
    echo ERROR: please install libtoolize or glibtoolize before running this script
fi
set -x
rm -f config.cache acconfig.h aclocal.m4 config.guess config.sub ltmain.sh
$lcmd
cat m4/*.m4 > acinclude.m4
aclocal -I m4
autoconf
#acconfig
autoheader
automake -a

