lab5: AuthEncryptor.o main.o
	gcc AuthEncryptor.o main.o -o lab5 -lstdc++ -lcrypto -lssl -std=c++11
AuthEncryptor.o: AuthEncryptor.cpp AuthEncryptor.h
	gcc -c AuthEncryptor.cpp -std=c++11
main.o: main.cpp AuthEncryptor.h
	gcc -c main.cpp -std=c++11

clean:
	rm -f lab5 AuthEncryptor.o main.o
install:
	cp lab5 /usr/local/bin/lab5
uninstall:
	rm -f /usr/local/bin/lab5
