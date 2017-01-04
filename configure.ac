AC_INIT([grewrite], [0.1.0])
AM_INIT_AUTOMAKE
AC_PROG_CC
AC_SEARCH_LIBS([nfq_open], [netfilter_queue], [], [
  AC_MSG_ERROR([unable to find the nfq_open() function, have you installed libnetfiler_queue?])
])
AC_CONFIG_FILES([Makefile])
AC_OUTPUT
