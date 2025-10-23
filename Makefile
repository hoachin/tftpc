CC = clang
CFLAGS = -std=c23 -Wall -Wextra -pedantic -Werror
TARGET = ./target/tftp-client
SRC = tftp-client.c
HEADERS = tftp-client.h

all: $(TARGET)

$(TARGET): $(SRC) $(HEADERS)
	$(CC) $(CFLAGS) $< -o $@

clean:
	rm -f $(TARGET)

.PHONY: all clean
