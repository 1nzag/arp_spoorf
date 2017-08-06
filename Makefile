all: arp_spoorf

arp_spoorf: arp_lib.o main.o
	gcc -o arp_spoorf arp_lib.o main.o -lpcap -lpthread

arp_lib.o: arp_lib.c arp_lib.h
	gcc -c -o arp_lib.o arp_lib.c -lpcap

main.o: main.c arp_lib.h
	gcc -c -o main.o main.c -lpthread

clean:
	rm main.o arp_lib.o


