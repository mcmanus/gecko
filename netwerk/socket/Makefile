#
# Build sdt-proxy
#
TARGET = sdt-proxy

SRCROOT=../..

# TODO: figure out this directory name better
OBJROOT=$(SRCROOT)/obj-x86_64-pc-linux-gnu

CFLAGS= -I $(OBJROOT)/dist/include/ \
  -I $(OBJROOT)/dist/include/nss    \
  -I $(OBJROOT)/dist/include/nspr   \
  -I $(SRCROOT)/nsprpub/pr/include  \
  -L $(OBJROOT)/dist/lib/           \

CXXFLAGS = $(CFLAGS)

CFLAGS+=-pedantic -Wall

LINKOBJS = $(OBJROOT)/dist/lib/libssl3.so $(OBJROOT)/dist/lib/libnss3.so

LIBS = -lnspr4

OBJS = sdt-proxy.o sdt.o tcp_cubic.o tcp_general.o uLayer.o

$(TARGET): $(OBJS) Makefile
	$(CXX) -g $(OBJS) -o $(TARGET) $(CFLAGS) $(LINKOBJS) $(LIBS)

%.o : %.c Makefile sdt.h sdt_common.h
	$(CC) -g -c $(CFLAGS) $<

%.o : %.cpp Makefile
	$(CXX) -g -c $(CXXFLAGS) $<

clean:
	rm -f $(OBJS) $(TARGET)
