

LDFLAGS += -lnss3 -lnssutil3 -lsmime3 -lssl3 -lplds4 -lplc4 -lnspr4
CXXFLAGS += -I/home/mcmanus/src/mozilla2/wd/dist/public/nss/ -I/usr/include/nspr

OBJS += MozQuic.o
OBJS += MozQuicStream.o
OBJS += NSSHelper.o

all: client server

client: $(OBJS) sample/client.o
	g++ -o client $(OBJS) sample/client.o $(LDFLAGS)

server: $(OBJS) sample/server.o
	g++ -o server $(OBJS) sample/server.o $(LDFLAGS)

.PHONY: clean
clean:
	rm -f $(OBJS) client server sample/client.o sample/server.o

