aes: main.o
	gcc main.o -o aes -lstdc++ -lcrypto -lssl
main.o: main.cpp
	gcc -c main.cpp

clean:
	rm -f aes main.o
install:
	cp aes /usr/local/bin/aes
uninstall:
	rm -f /usr/local/bin/aes
