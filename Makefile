CC=gcc
SOURCES=risc_v_disassembler.c
EXECUTABLE=disas_risc_v
EXAMPLE1=first
EXAMPLE2=second
EXAMPLE3=third

all: compile

compile:
	$(CC) $(SOURCES) -o $(EXECUTABLE)

example1:
	$(EXECUTABLE) $(EXAMPLE1).hex rv64 >> $(EXAMPLE1).out

example2:
	$(EXECUTABLE) $(EXAMPLE2).hex rv64 >> $(EXAMPLE2).out

example3:
	$(EXECUTABLE) $(EXAMPLE3).hex rv64 >> $(EXAMPLE3).out

examples: compile example1 example2 example3