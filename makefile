all: Sniffer Spoffer Gateway Sniffandspoff
Sniffer: Sniffer.c
	gcc Sniffer.c -o Sniffer -lpcap
Spoffer: Spoffer.c
	gcc Spoffer.c -o Spoffer
Gateway: Gateway.c
	gcc Gateway.c -o Gateway
Sniffandspoff: Sniffandspoff.c
	gcc Sniffandspoff.c -o Sniffandspoff -lpcap
clean:
	rm -f *.o Sniffer Spoffer Gateway Sniffandspoff
