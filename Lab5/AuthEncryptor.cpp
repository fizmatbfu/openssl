// Copyright (C) 2020 Elmir Kurakin
// OpenSSL Auth Encryption and Decryption

#include "AuthEncryptor.h"
#include <openssl/err.h>


//some params are not same in some methods. here we set this params, including OpenSSL defined commands like EVP_CTRL_GCM_SET_IVLEN
AuthEncryptor::AuthEncryptor(const EVP_CIPHER* cipher, int setIvLengthParam, int ivLength, int getTagParam, int setTagParam, int tagLength)
    : cipher(cipher)
    , ivLength(ivLength)
    , setIvLengthParam(setIvLengthParam)
    , getTagParam(getTagParam)
    , setTagParam(setTagParam)
    , tagLength(tagLength)
{}


//encrypt func. encrypted text will be returned, calculated tag will be store in tag pointer
std::string AuthEncryptor::encrypt(const std::string &plainText, const std::string &key, const std::string &iv, unsigned char *tag)
{
    EVP_CIPHER_CTX *ctx;
    int len;
    int ciphertext_len;

    // Create and initialise the context
    if (!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors();

    // Initialise the encryption operation.
    if (1 != EVP_EncryptInit_ex(ctx, cipher, NULL, NULL, NULL))
        handleErrors();

    // Set IV length 
    if (1 != EVP_CIPHER_CTX_ctrl(ctx, setIvLengthParam, ivLength, NULL))
        handleErrors();

    // Set tag Length
    EVP_CIPHER_CTX_ctrl(ctx, setTagParam, tagLength, NULL);

    // Initialise key and IV 
    if (1 != EVP_EncryptInit_ex(ctx, NULL, NULL, reinterpret_cast<const unsigned char*>(key.data()), reinterpret_cast<const unsigned char*>(iv.data())))
        handleErrors();

    unsigned char *ciphertext = new unsigned char[plainText.size()];

    // Provide the message to be encrypted, and obtain the encrypted output.
    if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, reinterpret_cast<const unsigned char*>(plainText.data()), plainText.size()))
        handleErrors();
    ciphertext_len = len;

    // Finalise the encryption.
    if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
        handleErrors();
    ciphertext_len += len;

    // Get the tag
    if (1 != EVP_CIPHER_CTX_ctrl(ctx, getTagParam, tagLength, tag))
        handleErrors();

    // Clean up
    EVP_CIPHER_CTX_free(ctx);

    const std::string encryptedMessage = std::string(ciphertext, ciphertext + ciphertext_len / sizeof(unsigned char));
    delete[] ciphertext;

    return encryptedMessage;
}


//decrypt func. decrypted text will be returned. if something will be wrong, function will return empty string
std::string AuthEncryptor::decrypt(const std::string &cipherText, const std::string &key, const std::string &iv, unsigned char *tag)
{
    EVP_CIPHER_CTX *ctx;
    int len;
    int plaintext_len;
    int ret;

    // Create and initialise the context
    if (!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors();

    // Initialise the decryption operation.
    if (1 != EVP_DecryptInit_ex(ctx, cipher, NULL, NULL, NULL))
        handleErrors();

    // Setting iv length
    if (1 != EVP_CIPHER_CTX_ctrl(ctx, setIvLengthParam, ivLength, NULL))
        handleErrors();

    // Set expected tag value.
    if (1 != EVP_CIPHER_CTX_ctrl(ctx, setTagParam, tagLength, tag))
        handleErrors();

    // Initialise key and IV */
    if (1 != EVP_DecryptInit_ex(ctx, NULL, NULL, reinterpret_cast<const unsigned char*>(key.data()), reinterpret_cast<const unsigned char*>(iv.data())))
        handleErrors();

    unsigned char *plaintext = new unsigned char[cipherText.size()];

    // Provide the message to be decrypted, and obtain the plaintext output.
    ret = EVP_DecryptUpdate(ctx, plaintext, &len, reinterpret_cast<const unsigned char*>(cipherText.data()), cipherText.size());

    plaintext_len = len;

    // Clean up
    EVP_CIPHER_CTX_free(ctx);

    const std::string decryptedMessage = ret > 0 //success or not
        ? std::string(plaintext, plaintext + plaintext_len / sizeof(unsigned char))
        : std::string();
    delete[] plaintext;

    return decryptedMessage;
}


//print last error info and abort. called if some openssl function returned not 1 (not success)
void AuthEncryptor::handleErrors()
{
    ERR_print_errors_fp(stderr);
    abort();
}