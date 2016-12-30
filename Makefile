all:
	gcc -c -Wall -O2 -pedantic grewrite.c nfqueue.c tuntap.c && gcc -Wall grewrite.o nfqueue.o tuntap.o -o grewrite -lnetfilter_queue

