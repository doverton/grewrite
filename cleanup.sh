#!/bin/sh
# Remove all generated autotools files.
if [ -f Makefile ]; then
  make distclean
fi
rm -f Makefile.in aclocal.m4 compile configure depcomp install-sh missing
rm -Rf autom4te.cache
