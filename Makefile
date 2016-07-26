all: bin/sniffer

bin/sniffer: src/main.c
	gcc src/main.c -o bin/sniffer -lpcap

run:
	sudo ./bin/sniffer

clean:
	rm -rf bin/*
