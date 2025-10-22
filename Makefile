CC = clang
CFLAGS = -std=c23 -Wall -Wextra -pedantic -Werror
TARGET = ./target/tftp-client
SRC = tftp-client.c

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) $< -o $@

clean:
	rm -f $(TARGET)

.PHONY: all clean
