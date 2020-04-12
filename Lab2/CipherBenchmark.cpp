// Copyright (C) 2020 Elmir Kurakin
// CipherBenchmark.cpp

#include "CipherBenchmark.h"
#include "CommonConstants.h"
#include <openssl/des.h>
#include <iostream>
#include <iomanip>

const size_t kSetw = 10;
const char kDelimiter = '|';
constexpr size_t kSizeOfUnsignedCharBits = sizeof(unsigned char) * 8;


//print header of table
void CipherBenchmark::printHeader()
{
    std::cout 
        << std::setw(kSetw) << "Cipher" << kDelimiter 
        << std::setw(kSetw) << "Key size" << kDelimiter 
        << std::setw(kSetw) << "Block size" << kDelimiter 
        << std::setw(kSetw) << "Perfomance (MB/sec)\n";
}


//test 3DES Cipher. plainText - pointer to plain text, cipherText - pointer to store cipherText
void CipherBenchmark::test3DES(unsigned char *plainText, size_t plainTextLength, unsigned char *cipherText)
{
    /* Triple DES key for Encryption and Decryption */
    DES_cblock Key1 = { 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11 };
    DES_cblock Key2 = { 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22 };
    DES_cblock Key3 = { 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33 };
    DES_key_schedule SchKey1, SchKey2, SchKey3;

    const size_t keyLength = DES_KEY_SZ * kSizeOfUnsignedCharBits;
    const size_t blockSize = sizeof(DES_cblock) * kSizeOfUnsignedCharBits;

    const auto start = std::chrono::steady_clock::now();

    DES_set_key_checked(&Key1, &SchKey1);
    DES_set_key_checked(&Key2, &SchKey2);
    DES_set_key_checked(&Key3, &SchKey3);

    for (size_t i = 0; i < plainTextLength / sizeof(DES_cblock); i++)
    {
        DES_ecb3_encrypt(reinterpret_cast<DES_cblock*>(plainText + i * sizeof(DES_cblock)), reinterpret_cast<DES_cblock*>(cipherText + i * sizeof(DES_cblock)), &SchKey1, &SchKey2, &SchKey3, DES_ENCRYPT);
    }

    const auto end = std::chrono::steady_clock::now();
    printBenchmarkData("3DES", keyLength, blockSize, end - start);
}


//test EVPCipher. name - name for print, type - type of cipher, plainText - pointer to plain text, key - pointer to key, cipherText - pointer to store cipherText
void CipherBenchmark::testEVPCipher(const char *name, const EVP_CIPHER *type, unsigned char *plaintext, int plaintext_len, unsigned char *key, unsigned char *ciphertext)
{
    const auto start = std::chrono::steady_clock::now();
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

    if (EVP_EncryptInit_ex(ctx, type, NULL, key, NULL) == 1)
    {
        const int keyLength = EVP_CIPHER_CTX_key_length(ctx) * kSizeOfUnsignedCharBits;
        const int blockSize = EVP_CIPHER_CTX_block_size(ctx) * kSizeOfUnsignedCharBits;

        int len;

        EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len);
        EVP_EncryptFinal_ex(ctx, ciphertext + len, &len);

        const auto end = std::chrono::steady_clock::now();
        printBenchmarkData(name, keyLength, blockSize, end - start);
    }
    else
    {
        std::cerr << "Error init encryption\n";
    }

    EVP_CIPHER_CTX_free(ctx);
}


//print result of benchmark. name - name of cipher, duration - duration of encrypt all test data
void CipherBenchmark::printBenchmarkData(const char* name, size_t keyLength, size_t blockSize, const std::chrono::duration<double>& duration)
{
    const double speed = static_cast<double>(kNumOfMegabytesForTest) / duration.count();

    std::cout
        << std::setw(kSetw) << name << kDelimiter
        << std::setw(kSetw) << keyLength << kDelimiter
        << std::setw(kSetw) << blockSize << kDelimiter
        << std::setw(kSetw) << speed << std::endl;
}