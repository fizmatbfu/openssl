// Copyright (C) 2020 Elmir Kurakin
// OpenSSL Diffie–Hellman key exchange

#ifndef DH_KEY_GENERATOR_H__
#define DH_KEY_GENERATOR_H__

#include <openssl/evp.h>
#include <string>

class DHKeyGenerator
{
public:
    DHKeyGenerator();

    EVP_PKEY *generate();
    std::string derive(EVP_PKEY *peerkey);

private:
    void handleErrors();

private:
    EVP_PKEY *pkey;
};

#endif // !DH_KEY_GENERATOR_H__