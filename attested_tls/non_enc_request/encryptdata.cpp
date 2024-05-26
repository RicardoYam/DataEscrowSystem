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
#include <openssl/rand.h>
#include <openssl/aes.h>

#define PORT 4433

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

void handle_client(SSL *ssl, const unsigned char *encrypted_data, size_t encrypted_data_len, const unsigned char *iv, size_t iv_len)
{
    char buf[1024] = {0};
    int bytes_written;

    if (SSL_accept(ssl) <= 0)
    {
        fprintf(stderr, "SSL Handshake Failed: ");
        ERR_print_errors_fp(stderr);
    }
    else
    {
        printf("---------Write IV to client---------->\n");
        bytes_written = SSL_write(ssl, iv, iv_len);
        if (bytes_written <= 0)
        {
            fprintf(stderr, "Failed to send IV to client: ");
            ERR_print_errors_fp(stderr);
        }
        else
        {
            printf("Sent IV (%zu bytes) successfully.\n", iv_len);
        }

        printf("---------Write encrypted data to client---------->\n");
        bytes_written = SSL_write(ssl, encrypted_data, encrypted_data_len);
        if (bytes_written <= 0)
        {
            fprintf(stderr, "Failed to send encrypted data to client: ");
            ERR_print_errors_fp(stderr);
        }
        else
        {
            printf("Sent encrypted data (%zu bytes) successfully.\n", encrypted_data_len);
        }
    }

    SSL_shutdown(ssl);
    SSL_free(ssl);
}

void handleErrors()
{
    ERR_print_errors_fp(stderr);
    abort();
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

EVP_PKEY *generate_ephemeral_key()
{
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr);
    if (!pctx)
        handleErrors();
    if (EVP_PKEY_keygen_init(pctx) <= 0)
        handleErrors();
    if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, NID_X9_62_prime256v1) <= 0)
        handleErrors();

    EVP_PKEY *pkey = nullptr;
    if (EVP_PKEY_keygen(pctx, &pkey) <= 0)
        handleErrors();
    EVP_PKEY_CTX_free(pctx);

    return pkey;
}

std::vector<unsigned char> ecies_encrypt(EVP_PKEY *peerPublicKey, const std::string &plaintext, std::vector<unsigned char>& iv_out)
{
    // Generate temp key
    EVP_PKEY *myPrivateKey = generate_ephemeral_key();

    FILE *pubkey_file = fopen("temppublic.pem", "w");
    if (!pubkey_file)
        handleErrors();
    if (!PEM_write_PUBKEY(pubkey_file, myPrivateKey))
        handleErrors();
    fclose(pubkey_file);

    // derivation
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(myPrivateKey, nullptr);
    if (!ctx)
        handleErrors();
    if (EVP_PKEY_derive_init(ctx) <= 0)
        handleErrors();
    if (EVP_PKEY_derive_set_peer(ctx, peerPublicKey) <= 0)
        handleErrors();

    size_t secret_len;
    if (EVP_PKEY_derive(ctx, nullptr, &secret_len) <= 0)
        handleErrors();
    std::vector<unsigned char> secret(secret_len);
    if (EVP_PKEY_derive(ctx, secret.data(), &secret_len) <= 0)
        handleErrors();

    unsigned char key[EVP_MAX_KEY_LENGTH];
    unsigned char iv[AES_BLOCK_SIZE];
    EVP_Digest(secret.data(), secret_len, key, nullptr, EVP_sha256(), nullptr);
    RAND_bytes(iv, sizeof(iv));
    iv_out.assign(iv, iv + sizeof(iv)); 

    std::vector<unsigned char> ciphertext(plaintext.size() + AES_BLOCK_SIZE);
    int len = 0;
    int ciphertext_len = 0;

    EVP_CIPHER_CTX *encrypt_ctx = EVP_CIPHER_CTX_new();
    if (!encrypt_ctx)
        handleErrors();
    if (EVP_EncryptInit_ex(encrypt_ctx, EVP_aes_256_cbc(), nullptr, key, iv) != 1)
        handleErrors();
    if (EVP_EncryptUpdate(encrypt_ctx, ciphertext.data(), &len, reinterpret_cast<const unsigned char *>(plaintext.data()), plaintext.length()) != 1)
        handleErrors();
    ciphertext_len = len;
    if (EVP_EncryptFinal_ex(encrypt_ctx, ciphertext.data() + len, &len) != 1)
        handleErrors();
    ciphertext_len += len;

    ciphertext.resize(ciphertext_len);

    EVP_CIPHER_CTX_free(encrypt_ctx);
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(myPrivateKey);

    return ciphertext;
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

    const char *publicKeyFile = "public.pem";
    EVP_PKEY *peerPublicKey = read_public_key(publicKeyFile);
    if (!peerPublicKey) {
        std::cerr << "Failed to read public key." << std::endl;
        return 1;
    }

    std::string plaintext = "This is an encrypted data!";
    std::cout << "Plaintext: " << plaintext << std::endl;

    std::vector<unsigned char> iv;
    std::vector<unsigned char> ciphertext = ecies_encrypt(peerPublicKey, plaintext, iv);
    if (ciphertext.empty()) {
        std::cerr << "Encryption failed." << std::endl;
        EVP_PKEY_free(peerPublicKey);
        return 1;
    }

    std::cout << "Encrypted text: ";
    for (unsigned char c : ciphertext) {
        printf("%02x", c);
    }
    std::cout << std::endl;

    int client = accept(sock, (struct sockaddr *)&addr, &len);
    if (client < 0)
    {
        perror("Unable to accept");
        exit(EXIT_FAILURE);
    }

    ssl = SSL_new(ctx);
    SSL_set_fd(ssl, client);

    handle_client(ssl, ciphertext.data(), ciphertext.size(), iv.data(), iv.size());
    close(client);
    close(sock);
    SSL_CTX_free(ctx);
    cleanup_openssl();
    EVP_PKEY_free(peerPublicKey);

    return 0;
}
