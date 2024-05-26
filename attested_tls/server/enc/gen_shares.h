#ifndef GEN_SHARES_H
#define GEN_SHARES_H

#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <iostream>
#include <string>
#include <vector>
#include <string.h>
#include <cstddef>

// Structure to hold a key pair
struct KeyPair {
    unsigned char *private_key;
    int private_key_length;
    unsigned char *public_key;
    int public_key_length;
};

// Function to generate and return a key pair
KeyPair generate_and_return_key_pair();

// Function to convert binary data to a hex string
const char *generateHexString(unsigned char *der_data, size_t der_length);

// Function to generate a random large number (BIGNUM)
BIGNUM *generate_random_bignum(int bits);

// Function to print a BIGNUM
void print_bignum(BIGNUM *bn);

// Function to calculate polynomial points for secret sharing
char *get_polynomial_points(BIGNUM *slope, BIGNUM *b);

// Function to split the polynomial points into shares
char** get_shares(char *points);

#endif // GEN_SHARES_H
