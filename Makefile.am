AUTOMAKE_OPTIONS = foreign
bin_PROGRAMS = grewrite
grewrite_SOURCES = grewrite.c nfqueue.c tuntap.c pcap.c
grewrite_CFLAGS = -std=c11 -D_GNU_SOURCE -mtune=generic -flto -Wall -Wpedantic
grewrite_LDFLAGS = -flto
