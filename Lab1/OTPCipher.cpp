// Copyright (C) 2020 Elmir Kurakin
// OTPCipher.cpp

#include "OTPCipher.h"
#include <iostream>
#include <openssl/rand.h>

//generate key for encrypt. Lambda here is a length of key. returns generated key.
std::string OTPCipher::KeyGen(size_t lambda)
{
    unsigned char *key = new unsigned char[lambda];
    const int generateResult = RAND_bytes(key, lambda); //generates num random bytes using a cryptographically secure pseudo random generator
    //proof: https://www.openssl.org/docs/manmaster/man3/RAND_bytes.html

    if (generateResult != 1)
    {
        std::cerr << "Generate key error: RAND_bytes function returned code " << generateResult << std::endl;
    }

    const std::string retVal = std::string(key, key + lambda / sizeof(unsigned char));
    delete[] key;

    return retVal;
}


//encode plaintext (m parameter) with a key (k parameter). returns ciphertext
std::string OTPCipher::Enc(const std::string &k, const std::string &m)
{
    std::string ctext;
    ctext.resize(m.size());
    const size_t keySize = k.size();

    for (size_t i = 0; i < m.size(); i++)
    {
        ctext[i] = k[i % keySize] ^ m[i];
    }

    return ctext;
}


//decode ciphertext (c parameter) with a key (k parameter). returns decoded plaintext
std::string OTPCipher::Dec(const std::string &k, const std::string &c)
{
    std::string text;
    text.resize(c.size());
    const size_t keySize = k.size();

    for (size_t i = 0; i < c.size(); i++)
    {
        text[i] = k[i % keySize] ^ c[i];
    }

    return text;
}
