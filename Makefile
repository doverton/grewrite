all:
	gcc -c -Wall -O2 -pedantic grewrite.c nfqueue.c && gcc -Wall grewrite.o nfqueue.o -o grewrite -lnetfilter_queue

