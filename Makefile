CC=gcc
CFLAGS=-Wall -O2

pe_parser: pe_parser.c pe_parser.h
	$(CC) $(CFLAGS) -o pe_parser pe_parser.c

clean:
	rm -f pe_parser
