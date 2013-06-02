NAME = lua-mcrypt-baidu
VERSION = 0.1
DIST := $(NAME)-$(VERSION)

CC = gcc
RM = rm -rf

#If pkg-config is supported
# Name of .pc file. "lua5.1" on Debian/Ubuntu
# LUAPKG = lua5.1
# CFLAGS := $(pkg-config $(LUAPKG) --cflags)" -fPIC -O2 -Wall"
# LFLAGS = -shared
# INSTALL_PATH := $(pkg-config $(LUAPKG) --variable=INSTALL_CMOD)

#Else
CFLAGS = -Wall -fPIC -I/home/microwish/lib/libmcrypt/include -I/home/microwish/lua/include
#CFLAGS = -Wall -O2 -fPIC -I/home/microwish/lib/libmcrypt/include -I/home/microwish/lua/include
#LFLAGS = -shared -L/home/microwish/lib/libmcrypt/lib -lmcrypt -L/home/microwish/lua/lib -llua
LFLAGS = -shared -ldl  -L/home/microwish/lua/lib -llua -Wl,--rpath=/home/microwish/lib/libmcrypt/lib
INSTALL_PATH = /home/microwish/lua-mcrypt-baidu/lib

all: mcrypt.so

mcrypt.so: mcrypt.o
	$(CC) -o $@ $< $(LFLAGS)

mcrypt.o: lmcryptlib.c
	$(CC) -o $@ $(CFLAGS) -c $<

install: mcrypt.so
	install -D -s $< $(INSTALL_PATH)/$<

clean:
	$(RM) *.so *.o

dist:
	if [ -d $(DIST) ]; then $(RM) $(DIST); fi
	mkdir -p $(DIST)
	cp *.c Makefile $(DIST)/
	tar czvf $(DIST).tar.gz $(DIST)
	$(RM) $(DIST)

.PHONY: all clean dist
