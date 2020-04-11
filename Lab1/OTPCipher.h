// Copyright (C) 2020 Elmir Kurakin
// OTPCipher.h

#ifndef __OPENSSL_OTPCIPHER__
#define __OPENSSL_OTPCIPHER__

#include <string>

class OTPCipher
{
public:
    //generate key for encrypt. Lambda here is a length of key. returns generated key.
    static std::string KeyGen(size_t lambda);

    //encode plaintext (m parameter) with a key (k parameter). returns ciphertext
    static std::string Enc(const std::string &k, const std::string &m);

    //decode ciphertext (c parameter) with a key (k parameter). returns decoded plaintext
    static std::string Dec(const std::string &k, const std::string &c);
};

#endif // !__OPENSSL_OTPCIPHER__
