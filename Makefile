# Compiler and compiler flags
CC = gcc
CFLAGS = -g -Wall -Wextra -std=c11 

LDFLAGS = -lpcap

# Source files
SRCS = main.c helper.c

TARGET = cshark

all: $(TARGET)

$(TARGET): $(SRCS)
	$(CC) $(CFLAGS) -o $(TARGET) $(SRCS) $(LDFLAGS)

# Rule to clean up the generated executable
clean:
	rm -f $(TARGET)

.PHONY: all clean

