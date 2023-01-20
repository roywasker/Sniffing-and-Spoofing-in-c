all: Sniffer Spoffer Gateway
Sniffer: Sniffer.c
	gcc Sniffer.c -o Sniffer -lpcap
Spoffer: Spoffer.c
	gcc Spoffer.c -o Spoffer
Gateway: Gateway.c
	gcc Gateway.c -o Gateway

clean:
	rm -f *.o Sniffer Spoofer Gateway
