SHELLOBJS	= shell.o ext2.o disksim.o ext2_shell.o entrylist.o ext2_indirect.o
SRC=shell.c ext2.c disksim.c ext2_shell.c entrylist.c ext2_indirect.c
CC=gcc

all: $(SHELLOBJS)
	$(CC) -g -o shell $(SRC) -Wall
#	$(CC) -g -o shell $(SHELLOBJS) -Wall

clean:
	rm *.o
	rm shell
