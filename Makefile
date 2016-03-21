all: tt

#which comipler
CC = gcc

#where are include files kept
# INCLUDEM = /usr/include/mysql
INCLUDE = .

#options for development
CFLAGS = -g # -Wall -mlarge
#-mcmodel=medium	#not support in 32

#lib for mysql
# LIB = /usr/lib/mysql

tt: leak.o error.o 
		$(CC) $(CFLAGS) -o tt leak.o error.o 


error.o: error.c error.h 
		$(CC) $(CFLAGS) -c error.c 

leak.o: leak.c leak.h 
		$(CC) $(CFLAGS) -c leak.c 

clean:
		-rm *.o 
