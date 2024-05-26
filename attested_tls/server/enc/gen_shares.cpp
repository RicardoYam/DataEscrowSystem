#include "gen_shares.h"

KeyPair generate_and_return_key_pair()
{
    KeyPair keyPair = {nullptr, 0, nullptr, 0};
    EVP_PKEY_CTX *pkey_ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    EVP_PKEY *pkey = NULL;

    if (!pkey_ctx || EVP_PKEY_keygen_init(pkey_ctx) <= 0 ||
        EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pkey_ctx, NID_X9_62_prime256v1) <= 0 ||
        EVP_PKEY_keygen(pkey_ctx, &pkey) <= 0)
    {
        std::cerr << "Error during ECC key pair generation." << std::endl;
        if (pkey_ctx)
            EVP_PKEY_CTX_free(pkey_ctx);
        return keyPair;
    }

    BIO *bio_pub = BIO_new(BIO_s_mem());
    if (!bio_pub)
    {
        std::cerr << "Failed to create BIO for public key output." << std::endl;
        EVP_PKEY_free(pkey);
        return keyPair;
    }

    if (!PEM_write_bio_PUBKEY(bio_pub, pkey))
    {
        std::cerr << "Failed to write public key to BIO." << std::endl;
        BIO_free_all(bio_pub);
        EVP_PKEY_free(pkey);
        return keyPair;
    }

    char *pem_data_pub;
    long pem_len_pub = BIO_get_mem_data(bio_pub, &pem_data_pub);
    std::cout << "\nPublic Key in PEM Format:\n"
              << std::string(pem_data_pub, pem_len_pub) << std::endl;

    BIO *bio_priv = BIO_new(BIO_s_mem());
    if (!bio_priv)
    {
        std::cerr << "Failed to create BIO for private key output." << std::endl;
        BIO_free_all(bio_pub);
        EVP_PKEY_free(pkey);
        return keyPair;
    }

    if (!PEM_write_bio_PrivateKey(bio_priv, pkey, NULL, NULL, 0, NULL, NULL))
    {
        std::cerr << "Failed to write private key to BIO." << std::endl;
        BIO_free_all(bio_priv);
        BIO_free_all(bio_pub);
        EVP_PKEY_free(pkey);
        return keyPair;
    }

    char *pem_data_priv;
    long pem_len_priv = BIO_get_mem_data(bio_priv, &pem_data_priv);
    std::cout << "Private Key in PEM Format:\n"
              << std::string(pem_data_priv, pem_len_priv) << std::endl;

    // Serialize private key
    keyPair.private_key_length = i2d_PrivateKey(pkey, &keyPair.private_key);
    if (keyPair.private_key_length <= 0)
    {
        std::cerr << "Error serializing the private key." << std::endl;
    }

    // Serialize public key
    keyPair.public_key_length = i2d_PUBKEY(pkey, &keyPair.public_key);
    if (keyPair.public_key_length <= 0)
    {
        std::cerr << "Error serializing the public key." << std::endl;
    }

    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(pkey_ctx);

    return keyPair;
}

const char *generateHexString(unsigned char *der_data, size_t der_length)
{
    size_t hexStrLength = der_length * 2 + 1;
    char *hexString = (char *)malloc(hexStrLength);
    if (hexString == NULL)
    {
        return NULL;
    }

    char *ptr = hexString;
    for (size_t i = 0; i < der_length; ++i)
    {
        snprintf(ptr, 3, "%02x", der_data[i]);
        ptr += 2;
    }
    *ptr = '\0';

    return hexString;
}

BIGNUM *generate_random_bignum(int bits)
{
    BIGNUM *rand_num = BN_new();
    if (rand_num == NULL)
    {
        fprintf(stderr, "Error creating BIGNUM.\n");
        return NULL;
    }

    if (!BN_rand(rand_num, bits, BN_RAND_TOP_ANY, BN_RAND_BOTTOM_ANY))
    {
        ERR_print_errors_fp(stderr);
        BN_free(rand_num);
        return NULL;
    }

    return rand_num;
}

void print_bignum(BIGNUM *bn)
{
    char *num_str = BN_bn2dec(bn);
    if (num_str == NULL)
    {
        ERR_print_errors_fp(stderr);
        return;
    }
    printf("Random Big Number: %s\n", num_str);
    OPENSSL_free(num_str);
}

char *get_polynomial_points(BIGNUM *slope, BIGNUM *b)
{
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *x = BN_new();
    BIGNUM *share1 = BN_new();
    BIGNUM *share2 = BN_new();
    BIGNUM *two = BN_new();
    char *result = NULL;
    char *str1, *str2;

    BN_set_word(two, 2);

    BN_copy(share1, slope);
    BN_add(share1, share1, b);

    BN_mul(x, slope, two, ctx);
    BN_add(share2, x, b);

    str1 = BN_bn2hex(share1);
    str2 = BN_bn2hex(share2);

    int len = strlen(str1) + strlen(str2) + 7;
    result = (char *)malloc(len);
    if (result != NULL)
    {
        snprintf(result, len, "1-%s, 2-%s", str1, str2);
    }

    BN_free(x);
    BN_free(share1);
    BN_free(share2);
    BN_free(two);
    BN_CTX_free(ctx);
    OPENSSL_free(str1);
    OPENSSL_free(str2);

    return result;
}

char **get_shares(char *points)
{
    const char delim[3] = ", ";
    char **parts = (char **)malloc(2 * sizeof(char *));
    if (!parts)
        return NULL;

    int partIndex = 0;

    char *token = strtok(points, delim);
    while (token != NULL && partIndex < 2)
    {
        parts[partIndex++] = strdup(token);
        token = strtok(NULL, delim);
    }

    for (int i = partIndex; i < 2; i++)
    {
        parts[i] = NULL;
    }

    return parts;
}