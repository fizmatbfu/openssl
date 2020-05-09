// Copyright (C) 2020 Elmir Kurakin
// OpenSSL Auth Encryption and Decryption

#include <string>
#include <iostream>
#include <openssl/rand.h>
#include "AuthEncryptor.h"


// generate random String with length lambda with openssl
std::string generateRandomString(size_t lambda)
{
    unsigned char *key = new unsigned char[lambda];
    const int generateResult = RAND_bytes(key, lambda);

    if (generateResult != 1)
    {
        std::cerr << "Generate key error: RAND_bytes function returned code " << generateResult << std::endl;
    }

    const std::string retVal = std::string(key, key + lambda / sizeof(unsigned char));
    delete[] key;

    return retVal;
}


int main(int argc, char *argv[])
{
    // openssl has strange interface in function EVP_CTRL_***_SET_TAG, and casting from std::string is very complicated. I use char array for tag instead.
    unsigned char tag[16];

    const std::string plainText = "Nobody expects the Spanish Inquisition!";
    const std::string key = generateRandomString(16);
    const std::string iv = generateRandomString(16);

    AuthEncryptor gcmEncryptor(EVP_aes_256_gcm(), EVP_CTRL_GCM_SET_IVLEN, 16, EVP_CTRL_GCM_GET_TAG, EVP_CTRL_GCM_SET_TAG, 16);
    const std::string gcmEncryptedText = gcmEncryptor.encrypt(plainText, key, iv, tag);
    const std::string gcmDecryptedText =  gcmEncryptor.decrypt(gcmEncryptedText, key, iv, tag);

    std::cout << "\n GCM Auth Encryption/Decryption: " << std::endl
        << plainText << std::endl
        << gcmEncryptedText << std::endl
        << gcmDecryptedText << std::endl;

    AuthEncryptor ccmEncryptor(EVP_aes_256_ccm(), EVP_CTRL_CCM_SET_IVLEN, 7, EVP_CTRL_CCM_GET_TAG, EVP_CTRL_CCM_SET_TAG, 14);
    const std::string ccmEncryptedText = ccmEncryptor.encrypt(plainText, key, iv, tag);
    const std::string ccmDecryptedText = ccmEncryptor.decrypt(ccmEncryptedText, key, iv, tag);

    std::cout << "\n CCM Auth Encryption/Decryption: " << std::endl
        << plainText << std::endl
        << ccmEncryptedText << std::endl
        << ccmDecryptedText << std::endl;

    return 0;
}