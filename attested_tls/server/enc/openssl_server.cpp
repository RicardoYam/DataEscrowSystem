#include <arpa/inet.h>
#include <openenclave/enclave.h>
#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <openssl/rsa.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include "../../common/openssl_utility.h"
#include "gen_shares.h"
#include <openenclave/corelibc/stdlib.h>
#include <stdio.h>
#include <openenclave/seal.h>

static char *key1 = NULL;
static char *key2 = NULL;
static const char *publicHex = NULL;
static char *publicString = NULL;

int server_socket_fd = 0;
int client_socket_fd = 0;
int server_port_number = 0;

X509 *certificate = nullptr;
EVP_PKEY *pkey = nullptr;
SSL_CONF_CTX *ssl_confctx = SSL_CONF_CTX_new();

SSL_CTX *ssl_server_ctx = nullptr;
SSL *ssl_session = nullptr;

uint8_t *unsealed_data = NULL;
size_t unsealed_data_size = 0;

extern "C"
{
    void generate_keypair(uint8_t **out_sealed_blob, size_t *out_sealed_size);

    int set_up_tls_server(char *server_port, char *uuid_str);

    void unseal_data(uint8_t *sealed_blob, size_t sealed_size);

    int handle_communication_until_done(bool keep_server_up, char *additional_input);

    void free_tls();

    void enclave_helloworld();
};

void enclave_helloworld()
{
    // Call back into the host
    oe_result_t result = host_helloworld(publicString);
    if (result != OE_OK)
    {
        fprintf(
            stderr,
            "Call to host_helloworld failed: result=%u (%s)\n",
            result,
            oe_result_str(result));
    }
}

int verify_callback(int preverify_ok, X509_STORE_CTX *ctx);

int create_listener_socket(int port, int &server_socket)
{
    int ret = -1;
    const int reuse = 1;
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t)port);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);

    server_socket = socket(AF_INET, SOCK_STREAM, 0);

    if (server_socket < 0)
    {
        printf(TLS_SERVER "socket creation failed\n");
        goto exit;
    }

    if (setsockopt(
            server_socket,
            SOL_SOCKET,
            SO_REUSEADDR,
            (const void *)&reuse,
            sizeof(reuse)) < 0)
    {
        perror("TLS server: Setsockopt failed");
        goto exit;
    }

    if (bind(server_socket, (struct sockaddr *)&addr, sizeof(addr)) < 0)
    {
        perror("TLS server: Unable to bind socket to the port");
        goto exit;
    }

    if (listen(server_socket, 20) < 0)
    {
        perror("TLS server: Unable to open socket for listening");
        close(server_socket);
        goto exit;
    }
    ret = 0;
exit:
    return ret;
}

int handle_communication_until_done(
    bool keep_server_up,
    char *additional_input)
{
    int ret = -1;
    unsigned char buf[10];
    int read_len = 0;
    int bytes_read = 0;

waiting_for_connection_request:

    // reset ssl_session and client_socket_fd to prepare for the new TLS
    // connection
    close(client_socket_fd);
    SSL_free(ssl_session);
    printf(TLS_SERVER " waiting for client connection\n");

    struct sockaddr_in addr;
    uint len = sizeof(addr);

    client_socket_fd = accept(server_socket_fd, (struct sockaddr *)&addr, &len);

    if (client_socket_fd < 0)
    {
        perror("TLS server: Unable to accept the client request");
        goto exit;
    }

    // create a new SSL structure for a connection
    if ((ssl_session = SSL_new(ssl_server_ctx)) == nullptr)
    {
        printf(TLS_SERVER
               "Unable to create a new SSL connection state object\n");
        goto exit;
    }

    SSL_set_fd(ssl_session, client_socket_fd);

    // wait for a TLS/SSL client to initiate a TLS/SSL handshake
    if (SSL_accept(ssl_session) <= 0)
    {
        printf(TLS_SERVER " SSL handshake failed\n");
        goto exit;
    }

    if (additional_input != NULL)
    {
        if (strcmp(additional_input, (char *)UNSEAL) == 0)
        {
            printf(TLS_SERVER "<---- Read from client:\n");
            read_len = sizeof(buf) - 1;
            memset(buf, 0, sizeof(buf));
            bytes_read = SSL_read(ssl_session, buf, (size_t)read_len);
            printf("Received here: %s\n", buf);
            if (bytes_read <= 0)
            {
                printf("error\n");
            }

            if (strcmp((const char *)buf, CLIENT_PAYLOAD))
            {
                if (write_to_session_peer(
                        ssl_session, (char *)unsealed_data, unsealed_data_size) != 0)
                {
                    printf(TLS_SERVER " Write to client failed\n");
                    goto exit;
                }
            }
        }
        else
        {
            printf(TLS_SERVER "<---- Read from client:\n");
            read_len = sizeof(buf) - 1;
            memset(buf, 0, sizeof(buf));
            bytes_read = SSL_read(ssl_session, buf, (size_t)read_len);
            printf("Received: %s\n", buf);
            if (bytes_read <= 0)
            {
                printf("error\n");
            }

            if (strcmp((const char *)buf, CLIENT_PAYLOAD2))
            {
                if (write_to_session_peer(
                        ssl_session, additional_input, strlen(additional_input)) != 0)
                {
                    printf(TLS_SERVER " Write to client failed\n");
                    goto exit;
                }
            }

            if (strcmp((const char *)buf, CLIENT_PAYLOAD))
            {
                if (write_to_session_peer(
                        ssl_session, additional_input, strlen(additional_input)) != 0)
                {
                    printf(TLS_SERVER " Write to client failed\n");
                    goto exit;
                }
            }
        }
    }
    else
    {
        printf(TLS_SERVER "<---- Read from client:\n");
        read_len = sizeof(buf) - 1;
        memset(buf, 0, sizeof(buf));
        bytes_read = SSL_read(ssl_session, buf, (size_t)read_len);
        printf("Received: %s\n", buf);
        if (bytes_read <= 0)
        {
            printf("error\n");
        }

        printf(TLS_SERVER "<---- Write to client:\n");
        if (strcmp((const char *)buf, CLIENT_PAYLOAD))
        {
            if (write_to_session_peer(
                    ssl_session, publicHex, strlen(publicHex)) != 0)
            {
                printf(TLS_SERVER " Write to client failed\n");
                goto exit;
            }
        }

        if (strcmp((const char *)buf, CLIENT_PAYLOAD2))
        {
            if (write_to_session_peer(
                    ssl_session, key1, strlen(key1)) != 0)
            {
                printf(TLS_SERVER " Write to client failed\n");
                goto exit;
            }
        }
    }

    if (keep_server_up)
        goto waiting_for_connection_request;

    ret = 0;
exit:
    close(client_socket_fd);
    return ret;
}

int set_up_tls_server(char *server_port, char *uuid_str)
{
    int ret = 0;
    char *ptr = uuid_str;
    if (atoi(server_port) == 12341)
    {
        if (load_oe_modules() != OE_OK)
        {
            printf(TLS_SERVER "loading required Open Enclave modules failed\n");
            ret = -1;
            return ret;
        }

        if ((ssl_server_ctx = SSL_CTX_new(TLS_server_method())) == nullptr)
        {
            printf(TLS_SERVER "unable to create a new SSL context\n");
            ret = -1;
            return ret;
        }

        if (initalize_ssl_context(ssl_confctx, ssl_server_ctx) != OE_OK)
        {
            printf(TLS_SERVER "unable to create a initialize SSL context\n ");
            ret = -1;
            return ret;
        }

        SSL_CTX_set_verify(ssl_server_ctx, SSL_VERIFY_PEER, &verify_callback);

        if (load_tls_certificates_and_keys(ssl_server_ctx, certificate, pkey) != 0)
        {
            printf(TLS_SERVER
                   " unable to load certificate and private key on the server\n ");
            ret = -1;
            return ret;
        }

        server_port_number = atoi(server_port);

        printf("\n_uuid_sgx_ecdsa: ");
        for (int i = 0; i < 16; i++)
        {
            ptr += sprintf(ptr, "%02x", _uuid_sgx_ecdsa.b[i]);

            if (i == 3 || i == 5 || i == 7 || i == 9)
            {
                ptr += sprintf(ptr, "-");
            }
        }

        if (create_listener_socket(server_port_number, server_socket_fd) != 0)
        {
            printf(TLS_SERVER " unable to create listener socket on the server\n ");
            ret = -1;
            return ret;
        }
        return ret;
    }
}

void free_tls()
{
    if (client_socket_fd > 0)
        close(client_socket_fd);
    if (server_socket_fd > 0)
        close(server_socket_fd);

    if (ssl_session)
    {
        SSL_shutdown(ssl_session);
        SSL_free(ssl_session);
    }
    if (ssl_server_ctx)
        SSL_CTX_free(ssl_server_ctx);
    if (ssl_confctx)
        SSL_CONF_CTX_free(ssl_confctx);
    if (certificate)
        X509_free(certificate);
    if (pkey)
        EVP_PKEY_free(pkey);
    printf("free success\n");
}

void generate_keypair(uint8_t **out_sealed_blob, size_t *out_sealed_size)
{
    const char *privateHex = nullptr;
    BIGNUM *bnKey = BN_new();
    char *bnStr = nullptr;
    BIGNUM *bnRand = nullptr;
    char *points = nullptr;
    char **shares = nullptr;
    KeyPair keypair = {nullptr, 0, nullptr, 0};

    uint8_t *sealed_blob = NULL;
    size_t sealed_size = 0;
    oe_result_t result = OE_FAILURE;

    // der_data = generate_and_return_key_pair(der_length);
    keypair = generate_and_return_key_pair();

    privateHex = generateHexString(keypair.private_key, keypair.private_key_length);
    publicHex = generateHexString(keypair.public_key, keypair.public_key_length);
    publicString = (char *)keypair.public_key;

    // Convert the BIGNUM back to a decimal string for printing
    // bnStr = BN_bn2dec(bnKey);
    
    BN_hex2bn(&bnKey, privateHex);

    print_bignum(bnKey);
    
    // Random Big Number
    bnRand = generate_random_bignum(512);

    // print_bignum(bnRand);

    points = get_polynomial_points(bnRand, bnKey);

    // printf("Polynomial Points: %s\n", points);

    shares = get_shares(points);

    key1 = shares[0];
    key2 = shares[1];

    const char *opt_msg = "sealing";

    oe_seal_setting_t settings[] = {
        OE_SEAL_SET_POLICY(OE_SEAL_POLICY_UNIQUE)};

    result = oe_seal(
        NULL,
        settings,
        1,
        (const uint8_t *)key2,
        strlen(key2) + 1,
        (unsigned char *)opt_msg,
        strlen(opt_msg),
        &sealed_blob,
        &sealed_size);

    if (result != OE_OK)
    {
        oe_free(sealed_blob);
        sealed_blob = NULL;
        sealed_size = 0;
        fprintf(stderr, "Sealing failed: %s\n", oe_result_str(result));
    }

    *out_sealed_blob = sealed_blob;
    *out_sealed_size = sealed_size;

    // print shares
    // for (int i = 0; i < 2; i++)
    // {
    //     printf("Part %d: %s\n", i + 1, shares[i]);
    // }

    if (privateHex)
        free((void *)privateHex);
    if (bnKey)
        BN_free(bnKey);
    if (bnStr)
        OPENSSL_free(bnStr);
    if (bnRand)
        BN_free(bnRand);
    if (points)
        free(points);
    // if (shares)
    //     for (int i = 0; i < 2; i++)
    //     {
    //         if (shares[i] != nullptr)
    //         {
    //             free(shares[i]);
    //         }
    //     }
    //     free(shares);
}

void unseal_data(uint8_t *sealed_blob, size_t sealed_size)
{
    oe_result_t result;
    const char *opt_msg = "sealing";

    // Attempt to unseal the sealed blob
    result = oe_unseal(
        sealed_blob,
        sealed_size,
        (unsigned char *)opt_msg,
        strlen(opt_msg),
        &unsealed_data,
        &unsealed_data_size);

    if (result != OE_OK)
    {
        printf("Unsealing failed: %s\n", oe_result_str(result));
        // Optionally, handle specific error codes differently
        switch (result)
        {
        case OE_UNSUPPORTED:
            printf("The operation is not supported with the current enclave configuration.\n");
            break;
        case OE_INVALID_PARAMETER:
            printf("Invalid parameter passed to oe_unseal(). Check your buffers and lengths.\n");
            break;
        default:
            printf("An unexpected error occurred.\n");
        }
    }

    // Print unsealed data if it's null-terminated string
    if (unsealed_data != NULL)
    {
        // Optionally, ensure unsealed data is safe to print
        if (unsealed_data[unsealed_data_size - 1] == '\0')
        {
            printf("Unsealed data: %s\n", unsealed_data);
        }
        else
        {
            // For binary data, you would handle it differently
            printf("Unsealed data is binary and not null-terminated.\n");
        }
    }
}