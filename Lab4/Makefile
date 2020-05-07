aes: main.o
	gcc main.o -o lab4 -lstdc++ -lcrypto -lssl -std=c++11
main.o: main.cpp
	gcc -c main.cpp -std=c++11

clean:
	rm -f lab4 main.o
install:
	cp lab4 /usr/local/bin/lab4
uninstall:
	rm -f /usr/local/bin/lab4
