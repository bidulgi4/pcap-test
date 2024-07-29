# Variables
CC = gcc                    # Compiler
CFLAGS = -Wall -g           # Compiler flags (warnings and debugging)
LDFLAGS = -lpcap            # Linker flags for libpcap
TARGET = pcap-test          # Name of the final executable
SRC = pcap-test.c           # Source file

# Default rule to build the executable
all: $(TARGET)

# Rule to build the target executable
$(TARGET): $(SRC)
	$(CC) $(CFLAGS) $(SRC) -o $(TARGET) $(LDFLAGS)

# Rule to clean up generated files
clean:
	rm -f $(TARGET)

