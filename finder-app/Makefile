# Makefile for the writer application

# Default compiler setup
CC := ${CROSS_COMPILE}gcc

# Target binary
TARGET := writer

# Source files
SRCS := writer.c
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