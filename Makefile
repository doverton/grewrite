all:
	gcc -std=c11 -D_GNU_SOURCE -flto -c -Wall -march=native -O2 -Wpedantic grewrite.c nfqueue.c tuntap.c && gcc -flto -Wpedantic -Wall grewrite.o nfqueue.o tuntap.o -o grewrite -lnetfilter_queue

