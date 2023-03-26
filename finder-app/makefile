CROSS_COMPILE ?= aarch64-none-linux-gnu-
CC=$(CROSS_COMPILE)gcc

all:
	$(CC) -o writer writer.c
#CROSS_COMPILE:
#	$(CC) -o writer writer.c
clean:
	rm -f writer
	rm -f *.o
