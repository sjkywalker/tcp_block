all: tcp_block

tcp_block: main.o functions.o
	g++ -g -o tcp_block main.o functions.o -lpcap

main.o:
	g++ -g -c -o main.o main.cpp

functions.o:
	g++ -g -c -o functions.o functions.cpp

clean:
	rm -f *.o
	rm -f tcp_block

