CC = gcc
CFLAGS = -pipe  -O -W -Wall -Wpointer-arith -Wno-unused-parameter -Wunused-function -Wunused-variable -Wunused-value -Werror -g
LINK = $(CC) 

CORE_INCS = -I ./

default: main
main: objs/tail.o
	$(LINK) -o tail objs/tail.o

objs/tail.o: tail.c                                                              
	$(CC) -c $(CFLAGS) $(CORE_INCS) -o objs/tail.o tail.c
