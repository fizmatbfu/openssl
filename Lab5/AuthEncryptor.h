// Copyright (C) 2020 Elmir Kurakin
// OpenSSL Auth Encryption and Decryption

#include <openssl/evp.h>
#include <string>

class AuthEncryptor
{
public:
    AuthEncryptor(const EVP_CIPHER* cipher, int setIvLengthParam, int ivLength, int getTagParam, int setTagParam, int tagLength);

    AuthEncryptor(const AuthEncryptor&) = delete;
    AuthEncryptor& operator=(const AuthEncryptor&) = delete;

    std::string encrypt(const std::string &plainText, const std::string &key, const std::string &iv, unsigned char *tag);
    std::string decrypt(const std::string &cipherText, const std::string &key, const std::string &iv, unsigned char *tag);

private:
    void handleErrors();

private:
    const EVP_CIPHER* cipher;
    int setIvLengthParam;
    int ivLength;
    int getTagParam;
    int setTagParam;
    int tagLength;
};