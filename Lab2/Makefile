cipherbench: CipherBenchmark.o main.o
    gcc CipherBenchmark.o main.o -o cipherbench -lstdc++ -lcrypto -lssl
CipherBenchmark.o: CipherBenchmark.cpp CipherBenchmark.h
    gcc -c CipherBenchmark.cpp
main.o: main.cpp CipherBenchmark.h
    gcc -c main.cpp

clean:
    rm -f cipherbench CipherBenchmark.o main.o
install:
    cp cipherbench /usr/local/bin/cipherbench
uninstall:
    rm -f /usr/local/bin/cipherbench