// Copyright (C) 2020 Elmir Kurakin
// OpenSSL AES algorithm for file encryption/decryption

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <algorithm>
#include <iomanip>
#include <iostream>
#include <fstream>
#include <string>


const size_t kBufferSize = 50;
const std::string kDecryptedTextFileName = "decryptedText";


//encrypt function. plainText - text to encryption, key - key, iv - iv vector, cipherText - pointer to store encrypted text
void encryptText(unsigned char *plainText, size_t plainTextLength, unsigned char *key, unsigned char *iv, unsigned char *cipherText)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

    if (EVP_EncryptInit_ex(ctx, EVP_aes_128_ctr(), NULL, key, iv) == 1)
    {
        int len;

        EVP_EncryptUpdate(ctx, cipherText, &len, plainText, plainTextLength);
        EVP_EncryptFinal_ex(ctx, cipherText + len, &len);
    }
    else
    {
        std::cerr << "Error init encryption\n";
    }

    EVP_CIPHER_CTX_free(ctx);
}


//decrypt function. cipherText - text to decryption, key - key, iv - iv vector, plainText - pointer to store decrypted text
void decryptText(unsigned char *cipherText, size_t cipherTextLength, unsigned char *key, unsigned char *iv, unsigned char *plainText)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

    if (EVP_DecryptInit_ex(ctx, EVP_aes_128_ctr(), NULL, key, iv) == 1)
    {
        int len;

        EVP_DecryptUpdate(ctx, plainText, &len, cipherText, cipherTextLength);
        EVP_DecryptFinal_ex(ctx, plainText + len, &len);
    }
    else
    {
        std::cerr << "Error init decryption\n";
    }

    EVP_CIPHER_CTX_free(ctx);
}


//print text to screen
void printText(unsigned char *text, size_t textLength)
{
    for (size_t i=0 ; i<textLength; i++)
    {
        std::cout << text[i];
    }

    std::cout << std::endl;
}


int main(int argc, char* argv[])
{
    if (argc > 1)
    {
        //read plain text from file
        std::ifstream plainTextFile(argv[1], std::ios::binary);
        unsigned char plainText[kBufferSize];
        plainTextFile.read((char*)(&plainText[0]), kBufferSize);
        plainTextFile.close();

        //generate 256  bit key
        unsigned char key[256 / (sizeof(unsigned char) * 8)];
        RAND_bytes(key, sizeof(key));

        // generate 128 bit iv vector
        unsigned char iv[128 / (sizeof(unsigned char) * 8)];
        RAND_bytes(iv, sizeof(iv));

        //encrypt text
        unsigned char cipherText[kBufferSize];
        encryptText(plainText, kBufferSize, key, iv, cipherText);

        //write encrypted text to file
        std::ofstream cipherTextFile(kDecryptedTextFileName.data());
        cipherTextFile.write((char*)(&cipherText[0]), kBufferSize);
        cipherTextFile.close();

        //read encrypted text from file in other array
        std::ifstream encryptedTextFile(kDecryptedTextFileName.data(), std::ios::binary);
        unsigned char encryptedText[kBufferSize];
        encryptedTextFile.read((char*)(&encryptedText[0]), kBufferSize);

        //decrypt text from file
        unsigned char decryptedText[kBufferSize];
        decryptText(encryptedText, kBufferSize, key, iv, decryptedText);

        printText(plainText, kBufferSize);
        printText(decryptedText, kBufferSize);

        //compare plainText and decryptedText symbol-by-symbol
        for (size_t i = 0; i < kBufferSize; i++)
        {
            if (plainText[i] != decryptedText[i])
            {
                std::cout << "Error in symbol " << i << std::endl;
            }
        }
    }
    else
    {
        std::cout << "Usage: aes {NAME OF FILE TO ENCRYPT}\n";
    }

    return 0;
}