// Copyright (C) 2020 Elmir Kurakin
// CipherBenchmark.h

#ifndef __OPENSSL_CIPHERBENCHMARK__
#define __OPENSSL_CIPHERBENCHMARK__

#include <chrono>
#include <openssl/evp.h>

class CipherBenchmark
{
public:
    //print header of table
    static void printHeader();

    //test 3DES Cipher. plainText - pointer to plain text, cipherText - pointer to store cipherText
    static void test3DES(unsigned char *plainText, size_t plainTextLength, unsigned char *cipherText);

    //test EVPCipher. name - name for print, type - type of cipher, plainText - pointer to plain text, key - pointer to key, cipherText - pointer to store cipherText
    static void testEVPCipher(const char *name, const EVP_CIPHER *type, unsigned char *plaintext, int plaintext_len, unsigned char *key, unsigned char *ciphertext);

private:
    //print result of benchmark. name - name of cipher, duration - duration of encrypt all test data
    static void printBenchmarkData(const char *name, size_t keyLength, size_t blockSize, const std::chrono::duration<double> &duration);
};

#endif // !__OPENSSL_CIPHERBENCHMARK__