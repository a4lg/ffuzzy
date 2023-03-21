CC     = gcc
CFLAGS = -O2
OBJECTS = generate

all: $(OBJECTS)
clean:
	rm -f $(OBJECTS)

generate: generate.c Makefile
	$(CC) -o generate $(CFLAGS) generate.c -lfuzzy

.PHONY: all clean
