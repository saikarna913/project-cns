CC = g++
CFLAGS = -std=c++11 -Wall -Wextra
LDFLAGS = -lcrypto
SRCDIR = .
BUILDDIR = .

TARGETS = logappend logread

all: $(TARGETS)

logappend: $(SRCDIR)/main_logappend.cpp
	$(CC) $(CFLAGS) -o $(BUILDDIR)/$@ $< $(LDFLAGS)

logread: $(SRCDIR)/main_logread.cpp
	$(CC) $(CFLAGS) -o $(BUILDDIR)/$@ $< $(LDFLAGS)

clean:
	rm -f $(BUILDDIR)/logappend $(BUILDDIR)/logread

.PHONY: all clean