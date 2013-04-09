# Example makefile for CPE464 program 1
#
#  Remember to add /opt/csw/lib to your path in order to execute your program
#  under Solaris.  Putting something like:
#     [ -e "/opt/csw/lib" ] && export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/opt/csw/lib
#  in your ~/.mybashrc file should do the trick

CC = gcc
CFLAGS = -g -Wall
OS = $(shell uname -s)
PROC = $(shell uname -p)
EXEC_SUFFIX=$(OS)-$(PROC)

ifeq ("$(OS)", "SunOS")
	OSLIB=-L/opt/csw/lib -lsocket -lnsl
	OSINC=-I/opt/csw/include
	OSDEF=-DSOLARIS
else
ifeq ("$(OS)", "Darwin")
	OSLIB=
	OSINC=
	OSDEF=-DDARWIN
else
	OSLIB=
	OSINC=
	OSDEF=-DLINUX
endif
endif

all:  trace

trace: trace.c
	$(CC) $(CFLAGS) $(OSINC) $(OSLIB) $(OSDEF) -lpcap -o $@ trace.c checksum.c

test: trace
	./trace pcap/smallTCP.pcap

test2: trace
	./trace pcap/ArpTest.pcap




clean:
	rm -f trace
