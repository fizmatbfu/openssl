// Copyright (C) 2020 Elmir Kurakin
// OpenSSL ciphers benchmark

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <gost_grasshopper_cipher.h>
#include "CommonConstants.h"
#include "CipherBenchmark.h"


int main()
{
    CipherBenchmark::printHeader();

    unsigned char *plainText = new unsigned char[kSize];
    unsigned char *cipherText = new unsigned char[kSize];
    RAND_bytes(plainText, kSize);

    CipherBenchmark::test3DES(plainText, kSize, cipherText);

    unsigned char grasshopperKey[GRASSHOPPER_KEY_SIZE];
    RAND_bytes(grasshopperKey, GRASSHOPPER_KEY_SIZE);
    CipherBenchmark::testEVPCipher("GOST15", cipher_gost_grasshopper_cbc(), plainText, kSize, grasshopperKey, cipherText);

    unsigned char aes128Key[128 / sizeof(unsigned char)];
    RAND_bytes(aes128Key, 128 / sizeof(unsigned char));
    CipherBenchmark::testEVPCipher("AES128", EVP_aes_128_cbc(), plainText, kSize, aes128Key, cipherText);

    unsigned char aes256Key[256 / sizeof(unsigned char)];
    RAND_bytes(aes256Key, 256 / sizeof(unsigned char));
    CipherBenchmark::testEVPCipher("AES256", EVP_aes_256_cbc(), plainText, kSize, aes256Key, cipherText);


    delete[] plainText;
    delete[] cipherText;

    return 0;
}