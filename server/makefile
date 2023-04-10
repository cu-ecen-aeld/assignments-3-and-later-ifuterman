#------------------------------------------------------------------------------
# makefile for 5.1 assesment
#
# Use: make [PLATFORM] [TARGET]
#
# Build Targets:
#      
#      all - Builds and links all source files to predefined target
#	   default - Builds and links all source files to predefined target
#      clean - removes all generated files
#
#------------------------------------------------------------------------------
PLATFORM ?= HOST
CROSS_COMPILE = 

ifeq ($(PLATFORM), AARCH64)
	CROSS_COMPILE = aarch64-none-linux-gnu-
endif

CC=$(CROSS_COMPILE)gcc
CFLAGS = -Wall -Werror
LD = -pthread -lrt
#SOURCES = aesdsocket.c
#OBJ=$(SOURCES:.c=.o)
TARGET ?= aesdsocket

all:
	$(CC) -o $(TARGET) aesdsocket.c $(CFLAGS) $(LD)

default: all
	
.PHONY: clean
clean:
	rm -f *.o $(TARGET)
