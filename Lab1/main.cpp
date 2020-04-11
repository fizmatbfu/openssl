// Copyright (C) 2020 Elmir Kurakin
// Simple OTPCipher example

#include "OTPCipher.h"
#include <iostream>


int main()
{
    const std::string plainText = "Nobody expects the Spanish Inquisition!";

    const std::string key = OTPCipher::KeyGen(24);
    const std::string encoded = OTPCipher::Enc(key, plainText);
    const std::string decoded = OTPCipher::Dec(key, encoded);

    std::cout << "Key: \n" << key <<std::endl;
    std::cout << "Plain text:\n" << plainText << std::endl;
    std::cout << "Encrypted text:\n" << encoded << std::endl;
    std::cout << "Dectypted text:\n" << decoded << std::endl;

    return 0;
}