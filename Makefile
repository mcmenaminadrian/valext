all: valext

valext: main.o
	gcc -O2 -o valext -Wall main.o -lproc

main.o: valext.c
	gcc -O2 -o main.o -c -Wall valext.c
