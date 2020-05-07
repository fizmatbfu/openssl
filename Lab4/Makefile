aes: main.o
	gcc main.o -o lab4 -lstdc++ -lcrypto -lssl
main.o: main.cpp
	gcc -c main.cpp

clean:
	rm -f lab4 main.o
install:
	cp lab4 /usr/local/bin/lab4
uninstall:
	rm -f /usr/local/bin/lab4
