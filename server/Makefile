# Makefile for the server socket application

# Default compiler setup
CC := ${CROSS_COMPILE}gcc

# Target binary
TARGET := aesdsocket

# Source files
SRCS := aesdsocket.c
OBJS := $(SRCS:.c=.o)

# Default target
all: $(TARGET)

# Build rule
$(TARGET): $(OBJS)
	$(CC) $(OBJS) -o $@

# First compile the source files into object files
%.o: %.c
	$(CC) -c $< -o $@

# Clean rule
clean:
	rm -f $(OBJS) $(TARGET)

.PHONY: all clean