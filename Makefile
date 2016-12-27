all:
	gcc -c -Wall -O2 -pedantic grewrite.c && gcc -Wall grewrite.o -o grewrite -lnetfilter_queue

