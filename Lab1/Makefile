otp: OTPCipher.o main.o
	gcc OTPCipher.o main.o -o otp -lstdc++ -lcrypto -lssl
OTPCipher.o: OTPCipher.cpp OTPCipher.h
	gcc -c OTPCipher.cpp
main.o: main.cpp OTPCipher.h
	gcc -c main.cpp

clean:
	rm -f otp OTPCipher.o main.o
install:
	cp otp /usr/local/bin/otp
uninstall:
	rm -f /usr/local/bin/otp
