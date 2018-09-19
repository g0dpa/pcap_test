all: pcap_test

pcap_test: main.o
	gcc -o pcap_test main.o -lpcap

main.o: main.c
	gcc -c -o main.o main.c

clean:
	rm -f pcap_test
	rm -f main.o
