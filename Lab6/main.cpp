// Copyright (C) 2020 Elmir Kurakin
// OpenSSL Diffie�Hellman key exchange

#include <string>
#include <iostream>
#include "DHKeyGenerator.h"


int main(int argc, char *argv[])
{
    //keygenerators for alice and bob
    DHKeyGenerator alice, bob;

    EVP_PKEY *aliceKey = alice.generate();
    EVP_PKEY *bobKey = bob.generate();

    //each keygenerator stores own key for deriving
    const std::string aliceShared = alice.derive(bobKey);
    const std::string bobShared = bob.derive(aliceKey);

    if (aliceShared == bobShared)
    {
        std::cout << " OK: Shared's of Alice and Bob are identical\n";
    }
    else
    {
        std::cerr << " Error: Shared's aren't identical!\n";
    }

    return 0;
}