all:
	@gcc monster.c -Wall -g -lpcap -o test.o
clean:
	@rm test.o
