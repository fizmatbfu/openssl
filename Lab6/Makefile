lab6: DHKeyGenerator.o main.o
	gcc DHKeyGenerator.o main.o -o lab6 -lstdc++ -lcrypto -lssl -std=c++0x
DHKeyGenerator.o: DHKeyGenerator.cpp DHKeyGenerator.h
	gcc -c DHKeyGenerator.cpp -std=c++0x
main.o: main.cpp DHKeyGenerator.h
	gcc -c main.cpp -std=c++0x

clean:
	rm -f lab6 DHKeyGenerator.o main.o
install:
	cp lab6 /usr/local/bin/lab6
uninstall:
	rm -f /usr/local/bin/lab6