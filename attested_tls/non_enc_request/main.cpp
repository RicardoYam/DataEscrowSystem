#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <vector>
#include <string>
#include <iostream>
#include <fstream>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/bio.h>

#define PORT 4433

void handleErrors()
{
    ERR_print_errors_fp(stderr);
    abort();
}

EVP_PKEY *read_private_key(const char *filename)
{
    FILE *fp = fopen(filename, "rb");
    if (!fp)
    {
        std::cerr << "Unable to open file: " << filename << std::endl;
        return nullptr;
    }

    EVP_PKEY *pkey = PEM_read_PrivateKey(fp, nullptr, nullptr, nullptr);
    fclose(fp);

    if (!pkey)
    {
        std::cerr << "Error reading private key from file." << std::endl;
        ERR_print_errors_fp(stderr);
        return nullptr;
    }

    return pkey;
}

EVP_PKEY *read_public_key(const char *filename)
{
    FILE *fp = fopen(filename, "rb");
    if (!fp)
    {
        std::cerr << "Unable to open file: " << filename << std::endl;
        return nullptr;
    }

    EVP_PKEY *pkey = PEM_read_PUBKEY(fp, nullptr, nullptr, nullptr);
    fclose(fp);

    if (!pkey)
    {
        std::cerr << "Error reading public key from file." << std::endl;
        ERR_print_errors_fp(stderr);
        return nullptr;
    }

    return pkey;
}

void init_openssl()
{
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
}

void cleanup_openssl()
{
    EVP_cleanup();
}

int create_socket(int port)
{
    int s;
    struct sockaddr_in addr;

    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);

    s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0)
    {
        perror("Unable to create socket");
        exit(EXIT_FAILURE);
    }

    if (bind(s, (struct sockaddr *)&addr, sizeof(addr)) < 0)
    {
        perror("Unable to bind");
        exit(EXIT_FAILURE);
    }

    if (listen(s, 1) < 0)
    {
        perror("Unable to listen");
        exit(EXIT_FAILURE);
    }

    return s;
}

void handle_client(SSL *ssl, std::vector<unsigned char> &encrypted_data, std::vector<unsigned char> &iv)
{
    char response[] = "exchange";
    int bytes_read, bytes_written;

    if (SSL_accept(ssl) <= 0)
    {
        std::cerr << "SSL Handshake Failed: ";
        ERR_print_errors_fp(stderr);
    }
    else
    {
        std::cout << "---------Write to client---------->\n";
        bytes_written = SSL_write(ssl, response, strlen(response));
        if (bytes_written <= 0)
        {
            std::cerr << "Failed to send 'exchange' to client: ";
            ERR_print_errors_fp(stderr);
        }
        else
        {
            char share1_buf[1024] = {0};
            bytes_read = SSL_read(ssl, share1_buf, sizeof(share1_buf) - 1);
            if (bytes_read > 0)
            {
                share1_buf[bytes_read] = '\0';
                std::cout << "Received 'share1' from client.\n";

                std::ofstream share1_file("share1.txt", std::ofstream::binary);
                if (share1_file.is_open())
                {
                    share1_file.write(share1_buf, bytes_read);
                    share1_file.close();
                    std::cout << "'share1' written to 'share1.txt'\n";
                }
                else
                {
                    std::cerr << "Failed to open 'share1.txt'\n";
                }

                iv.resize(16);
                bytes_read = SSL_read(ssl, iv.data(), iv.size());
                if (bytes_read > 0)
                {
                    std::cout << "Received IV from client.\n";

                    encrypted_data.resize(1024);
                    bytes_read = SSL_read(ssl, encrypted_data.data(), encrypted_data.size());
                    if (bytes_read > 0)
                    {
                        std::cout << "Received encrypted data from client.\n";
                        encrypted_data.resize(bytes_read);
                    }
                    else
                    {
                        std::cerr << "Failed to receive encrypted data: ";
                        ERR_print_errors_fp(stderr);
                    }
                }
                else
                {
                    std::cerr << "Failed to receive IV: ";
                    ERR_print_errors_fp(stderr);
                }
            }
            else
            {
                std::cerr << "Failed to receive 'share1': ";
                ERR_print_errors_fp(stderr);
            }
        }
    }

    SSL_shutdown(ssl);
    SSL_free(ssl);
}

bool parse_point(const std::string &point, BIGNUM **x, BIGNUM **y)
{
    size_t dash_pos = point.find('-');
    if (dash_pos == std::string::npos)
    {
        return false;
    }

    std::string x_str = point.substr(0, dash_pos);
    std::string y_str = point.substr(dash_pos + 1);

    *x = BN_new();
    *y = BN_new();
    BN_dec2bn(x, x_str.c_str());
    BN_hex2bn(y, y_str.c_str());

    return true;
}

BIGNUM *calculate_b(const std::string &point1, const std::string &point2)
{
    BIGNUM *x1, *y1, *x2, *y2;
    if (!parse_point(point1, &x1, &y1) || !parse_point(point2, &x2, &y2))
    {
        std::cerr << "Error: Invalid point format." << std::endl;
        return nullptr;
    }

    // Calculate a = (y2 - y1) / (x2 - x1)
    BIGNUM *y2_minus_y1 = BN_new();
    BIGNUM *x2_minus_x1 = BN_new();
    BN_CTX *ctx = BN_CTX_new();
    BN_sub(y2_minus_y1, y2, y1);
    BN_sub(x2_minus_x1, x2, x1);

    if (BN_is_zero(x2_minus_x1))
    { // Check for division by zero
        std::cerr << "Error: Division by zero." << std::endl;
        BN_free(x1);
        BN_free(y1);
        BN_free(x2);
        BN_free(y2);
        BN_free(y2_minus_y1);
        BN_free(x2_minus_x1);
        BN_CTX_free(ctx);
        return nullptr;
    }

    BIGNUM *a = BN_new();
    BN_div(a, nullptr, y2_minus_y1, x2_minus_x1, ctx);

    // Calculate b = y1 - a*x1
    BIGNUM *ax1 = BN_new();
    BN_mul(ax1, a, x1, ctx);

    BIGNUM *b = BN_new();
    BN_sub(b, y1, ax1);

    // Cleanup
    BN_free(x1);
    BN_free(y1);
    BN_free(x2);
    BN_free(y2);
    BN_free(y2_minus_y1);
    BN_free(x2_minus_x1);
    BN_free(ax1);
    BN_free(a);
    BN_CTX_free(ctx);

    return b;
}

std::string readSingleLineFromFile(const std::string &filename)
{
    std::ifstream file(filename);
    std::string line;
    if (file.is_open())
    {
        if (!std::getline(file, line))
        {
            std::cerr << "Failed to read line from " << filename << std::endl;
        }
        file.close();
    }
    else
    {
        std::cerr << "Unable to open " << filename << std::endl;
    }
    return line;
}

unsigned char *hexStringToDer(const char *hexString, size_t *der_length)
{
    size_t hexStrLength = strlen(hexString);
    if (hexStrLength % 2 != 0)
    {
        return NULL;
    }

    *der_length = hexStrLength / 2;
    unsigned char *der_data = (unsigned char *)malloc(*der_length);
    if (der_data == NULL)
    {
        return NULL;
    }

    for (size_t i = 0; i < *der_length; ++i)
    {
        sscanf(hexString + 2 * i, "%2hhx", &der_data[i]);
    }

    return der_data;
}

std::vector<unsigned char> ecies_decrypt(EVP_PKEY *myPrivateKey, EVP_PKEY *senderPublicKey, const std::vector<unsigned char> &ciphertext, const std::vector<unsigned char> &iv)
{
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(myPrivateKey, nullptr);
    if (!ctx)
        handleErrors();
    if (EVP_PKEY_derive_init(ctx) <= 0)
        handleErrors();
    if (EVP_PKEY_derive_set_peer(ctx, senderPublicKey) <= 0)
        handleErrors();

    size_t secret_len;
    if (EVP_PKEY_derive(ctx, nullptr, &secret_len) <= 0)
        handleErrors();
    std::vector<unsigned char> secret(secret_len);
    if (EVP_PKEY_derive(ctx, secret.data(), &secret_len) <= 0)
        handleErrors();

    unsigned char key[EVP_MAX_KEY_LENGTH];
    EVP_Digest(secret.data(), secret_len, key, nullptr, EVP_sha256(), nullptr);

    std::vector<unsigned char> plaintext(ciphertext.size());
    int len = 0;
    int plaintext_len = 0;

    EVP_CIPHER_CTX *decrypt_ctx = EVP_CIPHER_CTX_new();
    if (!decrypt_ctx)
        handleErrors();
    if (EVP_DecryptInit_ex(decrypt_ctx, EVP_aes_256_cbc(), nullptr, key, iv.data()) != 1)
        handleErrors();
    if (EVP_DecryptUpdate(decrypt_ctx, plaintext.data(), &len, ciphertext.data(), ciphertext.size()) != 1)
        handleErrors();
    plaintext_len = len;
    if (EVP_DecryptFinal_ex(decrypt_ctx, plaintext.data() + len, &len) != 1)
        handleErrors();
    plaintext_len += len;

    plaintext.resize(plaintext_len);

    EVP_CIPHER_CTX_free(decrypt_ctx);
    EVP_PKEY_CTX_free(ctx);

    return plaintext;
}

int main()
{
    int sock;
    SSL_CTX *ctx;

    init_openssl();
    ctx = SSL_CTX_new(TLS_server_method());

    if (!ctx)
    {
        perror("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    SSL_CTX_set_ecdh_auto(ctx, 1);

    // Set the key and cert
    if (SSL_CTX_use_certificate_file(ctx, "server.crt", SSL_FILETYPE_PEM) <= 0)
    {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, "server.key", SSL_FILETYPE_PEM) <= 0)
    {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    sock = create_socket(PORT);

    struct sockaddr_in addr;
    uint len = sizeof(addr);
    SSL *ssl;

    int client = accept(sock, (struct sockaddr *)&addr, &len);
    if (client < 0)
    {
        perror("Unable to accept");
        exit(EXIT_FAILURE);
    }

    ssl = SSL_new(ctx);
    SSL_set_fd(ssl, client);

    std::vector<unsigned char> encrypted_data;
    std::vector<unsigned char> iv;

    handle_client(ssl, encrypted_data, iv);
    close(client);

    std::string point1 = readSingleLineFromFile("share1.txt");
    std::string point2 = readSingleLineFromFile("share2.txt");

    BIGNUM *b = calculate_b(point1, point2);
    if (b)
    {
        char *b_hex = BN_bn2hex(b);

        size_t der_length;
        unsigned char *der_data = hexStringToDer(b_hex, &der_length);
        if (!der_data)
        {
            fprintf(stderr, "Failed to convert hex to DER.\n");
            OPENSSL_free(b_hex);
            BN_free(b);
            return 1;
        }

        EC_KEY *ec_key = d2i_ECPrivateKey(NULL, (const unsigned char **)&der_data, (long)der_length);
        if (!ec_key)
        {
            fprintf(stderr, "Failed to convert DER to ECC Private Key.\n");
            free(der_data);
            OPENSSL_free(b_hex);
            BN_free(b);
            return 1;
        }

        EVP_PKEY *pkey = EVP_PKEY_new();
        if (!EVP_PKEY_assign_EC_KEY(pkey, ec_key))
        {
            fprintf(stderr, "Failed to assign EC_KEY to EVP_PKEY.\n");
            EVP_PKEY_free(pkey);
            EC_KEY_free(ec_key);
            free(der_data);
            OPENSSL_free(b_hex);
            BN_free(b);
            return 1;
        }

        BIO *pem_bio = BIO_new_file("private.pem", "w");
        if (pem_bio)
        {
            if (!PEM_write_bio_PrivateKey(pem_bio, pkey, nullptr, nullptr, 0, nullptr, nullptr))
            {
                std::cerr << "Failed to write private key to PEM file." << std::endl;
            }
            BIO_free_all(pem_bio); // This will flush and close the file
        }
        else
        {
            std::cerr << "Failed to create PEM file BIO." << std::endl;
        }

        std::cout << "Recovered Private Key has been saved to 'private.pem'." << std::endl;

        const char *privateKeyFile = "private.pem";
        EVP_PKEY *myPrivateKey = read_private_key(privateKeyFile);
        if (!myPrivateKey)
        {
            std::cerr << "Failed to read private key." << std::endl;
            return 1;
        }

        const char *tempPublicKeyFile = "temppublic.pem";
        EVP_PKEY *senderPublicKey = read_public_key(tempPublicKeyFile);
        if (!senderPublicKey)
        {
            std::cerr << "Failed to read sender's public key." << std::endl;
            EVP_PKEY_free(myPrivateKey);
            return 1;
        }

        std::vector<unsigned char> decryptedText = ecies_decrypt(myPrivateKey, senderPublicKey, encrypted_data, iv);
        if (decryptedText.empty())
        {
            std::cerr << "Decryption failed." << std::endl;
            EVP_PKEY_free(myPrivateKey);
            EVP_PKEY_free(senderPublicKey);
            return 1;
        }

        std::cout << "Decrypted text: " << std::string(decryptedText.begin(), decryptedText.end()) << std::endl;

        EVP_PKEY_free(myPrivateKey);
        EVP_PKEY_free(senderPublicKey);
        EVP_cleanup();
        ERR_free_strings();

        EVP_cleanup();
        ERR_free_strings();

        EVP_PKEY_free(pkey);
        BIO_free_all(pem_bio);

        OPENSSL_free(b_hex);
        BN_free(b);
    }

    close(sock);
    SSL_CTX_free(ctx);
    cleanup_openssl();
}
