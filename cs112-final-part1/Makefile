LLHTTP_DIR = ../../llhttp
OPENSSL_CFLAGS := $(shell pkg-config --cflags openssl)
OPENSSL_LIBS   := $(shell pkg-config --libs openssl)
src = $(wildcard *.c) \
	  $(LLHTTP_DIR)/src/native/api.c \
	  $(LLHTTP_DIR)/src/native/http.c \
	  $(LLHTTP_DIR)/build/c/llhttp.c
obj = $(src:.c=.o)
CC = gcc
IFLAGS = -I$(LLHTTP_DIR)/build
CFLAGS = $(OPENSSL_CFLAGS) $(IFLAGS)
LDFLAGS = $(OPENSSL_LIBS)
LDLIBS = -ldl -pthread

proxy: $(obj)
	$(CC) $(CFLAGS) -o proxy $^ $(LDFLAGS) $(LDLIBS)

.PHONY: clean
clean:
	rm -f $(obj) proxy
