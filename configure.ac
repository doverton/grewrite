AC_INIT([grewrite], [0.1.0])
AM_INIT_AUTOMAKE
AC_PROG_CC
AC_SEARCH_LIBS([nfq_open], [netfilter_queue], [], [
  AC_MSG_ERROR([unable to find the nfq_open() function, have you installed libnetfilter_queue?])
])
AC_SEARCH_LIBS([pcap_open_live], [pcap], [], [
  AC_MSG_ERROR([unable to find the pcap_open_live() function, have you installed libpcap?])
])
AC_CONFIG_FILES([Makefile])
AC_OUTPUT
