// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifdef _WIN32
#include <ws2tcpip.h>
#define close closesocket
#else
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <resolv.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

#include <openenclave/host.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <iostream>
#include <vector>
#include <cstring>
#include <fstream>
#include <cctype>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/aes.h>
#include <openssl/hmac.h>

#include "../common/common.h"

extern std::vector<std::string> messages;
std::vector<std::string> messages;
size_t messages_count = 0;

void print_key_info(EVP_PKEY *pkey)
{
    BIO *bio = BIO_new(BIO_s_mem());
    if (!bio)
    {
        std::cerr << "Failed to create BIO\n";
        return;
    }

    if (EVP_PKEY_id(pkey) == EVP_PKEY_RSA || EVP_PKEY_id(pkey) == EVP_PKEY_RSA_PSS)
    {
        std::cout << "Key Type: RSA" << std::endl;
    }
    else if (EVP_PKEY_id(pkey) == EVP_PKEY_EC)
    {
        std::cout << "Key Type: EC" << std::endl;
    }
    else
    {
        std::cout << "Key Type: Unknown" << std::endl;
    }

    if (EVP_PKEY_base_id(pkey) == EVP_PKEY_EC)
    {
        if (PEM_write_bio_EC_PUBKEY(bio, EVP_PKEY_get1_EC_KEY(pkey)))
        {
            std::cout << "EC Public Key:" << std::endl;
        }
    }
    else
    {
        if (PEM_write_bio_PUBKEY(bio, pkey))
        {
            std::cout << "Public Key:" << std::endl;
        }
    }

    char *data;
    long len = BIO_get_mem_data(bio, &data);
    if (len > 0)
    {
        std::cout.write(data, len);
        std::cout << std::endl;
    }

    BIO_reset(bio);
    if (PEM_write_bio_PrivateKey(bio, pkey, nullptr, nullptr, 0, nullptr, nullptr))
    {
        std::cout << "Private Key:" << std::endl;
        len = BIO_get_mem_data(bio, &data);
        if (len > 0)
        {
            std::cout.write(data, len);
            std::cout << std::endl;
        }
    }

    BIO_free(bio);
}

void hexStringToByteArray(const std::string &hexString, std::vector<unsigned char> &byteArray)
{
    size_t hexLength = hexString.length();
    byteArray.clear();
    byteArray.reserve(hexLength / 2);
    for (size_t i = 0; i < hexLength; i += 2)
    {
        std::string byteString = hexString.substr(i, 2);
        byteArray.push_back(static_cast<unsigned char>(strtol(byteString.c_str(), nullptr, 16)));
    }
}

bool savePublicKeyPEM(EVP_PKEY *pkey, const std::string &filename)
{
    FILE *fp = fopen(filename.c_str(), "w");
    if (!fp)
        return false;

    bool result = PEM_write_PUBKEY(fp, pkey);
    fclose(fp);
    return result;
}

int verify_callback(int preverify_ok, X509_STORE_CTX *ctx);
int create_socket(char *server_name, char *server_port);

int parse_arguments(
    int argc,
    char **argv,
    char **server_name,
    char **server_port)
{
    int ret = 1;
    const char *option = nullptr;
    int param_len = 0;

    if (argc != 3)
        goto print_usage;

    option = "-server:";
    param_len = strlen(option);
    if (strncmp(argv[1], option, param_len) != 0)
        goto print_usage;
    *server_name = (char *)(argv[1] + param_len);

    option = "-port:";
    param_len = strlen(option);
    if (strncmp(argv[2], option, param_len) != 0)
        goto print_usage;

    *server_port = (char *)(argv[2] + param_len);
    ret = 0;
    goto done;

print_usage:
    printf(TLS_CLIENT "Usage: %s -server:<name> -port:<port>\n", argv[0]);
done:
    return ret;
}

int communicate_with_server(SSL *ssl)
{
    unsigned char buf[245];
    int ret = 1;
    int error = 0;
    int len = 0;
    int bytes_written = 0;
    int bytes_read = 0;

    printf(TLS_CLIENT "-----> Write to server:\n");
    len = snprintf((char *)buf, sizeof(buf) - 1, CLIENT_PAYLOAD2);
    while ((bytes_written = SSL_write(ssl, buf, (size_t)len)) <= 0)
    {
        error = SSL_get_error(ssl, bytes_written);
        if (error == SSL_ERROR_WANT_WRITE)
            continue;
        printf(TLS_CLIENT "Failed! SSL_write returned %d\n", error);
        ret = bytes_written;
        goto done;
    }

    printf(TLS_CLIENT "<---- Read from server:\n");
    while ((bytes_read = SSL_read(ssl, buf, sizeof(buf) - 1)) > 0)
    {
        buf[bytes_read] = '\0';
        std::string message(reinterpret_cast<char *>(buf));

        if (strncmp(message.c_str(), "2-", 2) == 0)
        {
            std::ofstream file("share2.txt", std::ios::app);
            if (file.is_open())
            {
                file << message << std::endl;
                std::cout << "share2 stored in 'share2.txt'" << std::endl;
                file.close();
            }
            else
            {
                std::cerr << "Failed to open 'share2.txt' for writing." << std::endl;
            }
        }
        else
        {
            std::vector<unsigned char> binaryData;
            hexStringToByteArray(message, binaryData);

            const unsigned char *pData = binaryData.data();
            EVP_PKEY *pubKey = d2i_PUBKEY(nullptr, &pData, binaryData.size());
            if (pubKey)
            {
                if (!savePublicKeyPEM(pubKey, "public.pem"))
                {
                    std::cerr << "Failed to save public key to 'public.pem'." << std::endl;
                }
                std::cout << "Public key stored in 'public.pem'" << std::endl;
                EVP_PKEY_free(pubKey);
            }
            else
            {
                std::cerr << "Failed to convert binary data to a public key." << std::endl;
            }
        }
    }

    if (bytes_read < 0)
    {
        int err = SSL_get_error(ssl, bytes_read);
        if (err != SSL_ERROR_WANT_READ && err != SSL_ERROR_WANT_WRITE)
        {
            std::cerr << "SSL read error: " << err << std::endl;
        }
    }

    printf(TLS_CLIENT "-----> Write to server:\n");
    len = snprintf((char *)buf, sizeof(buf) - 1, CONNECTION_DONE);
    while ((bytes_written = SSL_write(ssl, buf, (size_t)len)) <= 0)
    {
        error = SSL_get_error(ssl, bytes_written);
        if (error == SSL_ERROR_WANT_WRITE)
            continue;
        printf(TLS_CLIENT "Failed! SSL_write returned %d\n", error);
        ret = bytes_written;
        goto done;
    }

    ret = 0;

done:
    return ret;
}

int create_socket(char *server_name, char *server_port)
{
    int sockfd = -1;
    char *addr_ptr = nullptr;
    int port = 0;
    struct addrinfo hints, *dest_info, *curr_di;
    int res;

#ifdef _WIN32
    WSADATA wsaData;
    if ((res = WSAStartup(MAKEWORD(2, 2), &wsaData)) != 0)
    {
        printf(TLS_CLIENT "Error: WSAStartup failed: %d\n", res);
        goto done;
    }
#endif

    hints = {0};
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    if ((res = getaddrinfo(server_name, server_port, &hints, &dest_info)) != 0)
    {
        printf(
            TLS_CLIENT "Error: Cannot resolve hostname %s. %s\n",
            server_name,
            gai_strerror(res));
        goto done;
    }

    curr_di = dest_info;
    while (curr_di)
    {
        if (curr_di->ai_family == AF_INET)
        {
            break;
        }

        curr_di = curr_di->ai_next;
    }

    if (!curr_di)
    {
        printf(
            TLS_CLIENT "Error: Cannot get address for hostname %s.\n",
            server_name);
        goto done;
    }

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd == -1)
    {
        printf(TLS_CLIENT "Error: Cannot create socket %d.\n", errno);
        goto done;
    }

    if (connect(
            sockfd,
            (struct sockaddr *)curr_di->ai_addr,
            sizeof(struct sockaddr)) == -1)
    {
        printf(
            TLS_CLIENT "failed to connect to %s:%s (errno=%d)\n",
            server_port,
            server_port,
            errno);
        close(sockfd);
        sockfd = -1;
        goto done;
    }
    printf(TLS_CLIENT "connected to %s:%s\n", server_name, server_port);

done:
    if (dest_info)
        freeaddrinfo(dest_info);

    return sockfd;
}

int main(int argc, char **argv)
{
    int ret = 1;
    X509 *cert = nullptr;
    SSL_CTX *ctx = nullptr;
    SSL *ssl = nullptr;
    int serversocket = 0;
    char *server_name = nullptr;
    char *server_port = nullptr;
    int error = 0;

    printf("\nStarting" TLS_CLIENT "\n\n\n");
    if ((error = parse_arguments(argc, argv, &server_name, &server_port)) != 0)
    {
        printf(
            TLS_CLIENT "TLS client:parse input parmeter failed (%d)!\n", error);
        goto done;
    }

    OpenSSL_add_all_algorithms();
    ERR_load_BIO_strings();
    ERR_load_crypto_strings();
    SSL_load_error_strings();

    if (SSL_library_init() < 0)
    {
        printf(TLS_CLIENT
               "TLS client: could not initialize the OpenSSL library !\n");
        goto done;
    }

    if ((ctx = SSL_CTX_new(SSLv23_client_method())) == nullptr)
    {
        printf(TLS_CLIENT "TLS client: unable to create a new SSL context\n");
        goto done;
    }

    SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2);
    SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv3);
    SSL_CTX_set_options(ctx, SSL_OP_NO_TLSv1);
    SSL_CTX_set_options(ctx, SSL_OP_NO_TLSv1_1);
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, &verify_callback);

    if ((ssl = SSL_new(ctx)) == nullptr)
    {
        printf(TLS_CLIENT
               "Unable to create a new SSL connection state object\n");
        goto done;
    }

    serversocket = create_socket(server_name, server_port);
    if (serversocket == -1)
    {
        printf(
            TLS_CLIENT
            "create a socket and initate a TCP connect to server: %s:%s "
            "(errno=%d)\n",
            server_name,
            server_port,
            errno);
        goto done;
    }

    SSL_set_fd(ssl, serversocket);
    if ((error = SSL_connect(ssl)) != 1)
    {
        printf(
            TLS_CLIENT "Error: Could not establish an SSL session ret2=%d "
                       "SSL_get_error()=%d\n",
            error,
            SSL_get_error(ssl, error));
        goto done;
    }
    printf(
        TLS_CLIENT "successfully established TLS channel:%s\n",
        SSL_get_version(ssl));

    if ((error = communicate_with_server(ssl)) != 0)
    {
        printf(TLS_CLIENT "Failed: communicate_with_server (ret=%d)\n", error);
        goto done;
    }

    if (serversocket != -1)
        close(serversocket);

    ret = 0;
done:
    if (ssl)
        SSL_free(ssl);

    if (cert)
        X509_free(cert);

    if (ctx)
        SSL_CTX_free(ctx);

    printf(TLS_CLIENT " %s\n", (ret == 0) ? "success" : "failed");
    return (ret);
    
}