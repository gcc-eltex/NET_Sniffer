SRC=$(wildcard src/*.c)
OBJ=$(patsubst src/%.c,%.o,$(SRC))


all: $(OBJ)
	gcc $(OBJ) -o bin/sniffer -lpcap
	rm -rf *.o

$(OBJ):	$(SRC)
	gcc $(SRC) -c

clean:
	rm -rf *.o bin/*

run:
	sudo ./bin/sniffer