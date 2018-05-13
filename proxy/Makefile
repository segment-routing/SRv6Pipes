CC=gcc
CFLAGS=-W -Wall -g -O2 -rdynamic
LDFLAGS=-ldl -pthread -lnetfilter_queue
EXEC=proxy

all: $(EXEC)

proxy: proxy.o hashmap.o llist.o
	$(CC) -o $@ $^ $(LDFLAGS) -export-dynamic

proxy.o: proxy.h hashmap.h llist.h
hashmap.o: llist.h

%.o: %.c
	$(CC) -o $@ -c $< $(CFLAGS)

clean:
	rm -rf *.o

mrproper: clean
	rm -rf $(EXEC)
