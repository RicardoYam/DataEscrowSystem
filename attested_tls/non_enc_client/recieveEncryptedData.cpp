#include <stdio.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

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

int create_socket()
{
    int s;
    struct sockaddr_in addr;

    addr.sin_family = AF_INET;
    addr.sin_port = htons(PORT);
    addr.sin_addr.s_addr = inet_addr("127.0.0.1");

    s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0)
    {
        perror("Unable to create socket");
        exit(EXIT_FAILURE);
    }

    if (connect(s, (struct sockaddr *)&addr, sizeof(addr)) < 0)
    {
        perror("Unable to connect");
        close(s);
        exit(EXIT_FAILURE);
    }

    return s;
}

void handle_server(SSL *ssl, size_t iv_size, size_t encrypted_data_size)
{
    unsigned char *iv = (unsigned char *)malloc(iv_size);
    if (!iv)
    {
        perror("Failed to allocate memory for IV");
        return;
    }

    unsigned char *encrypted_data = (unsigned char *)malloc(encrypted_data_size);
    if (!encrypted_data)
    {
        perror("Failed to allocate memory for encrypted data");
        free(iv);
        return;
    }

    int bytes_read = SSL_read(ssl, iv, iv_size);
    if (bytes_read <= 0)
    {
        int err = SSL_get_error(ssl, bytes_read);
        fprintf(stderr, "Failed to read IV with SSL error %d: ", err);
        ERR_print_errors_fp(stderr);
        free(iv);
        free(encrypted_data);
        return;
    }

    FILE *iv_file = fopen("iv.txt", "wb");
    if (iv_file == NULL)
    {
        perror("Failed to open 'iv.txt'");
        free(iv);
        free(encrypted_data);
        return;
    }
    fwrite(iv, 1, iv_size, iv_file);
    fclose(iv_file);

    bytes_read = SSL_read(ssl, encrypted_data, encrypted_data_size);
    if (bytes_read <= 0)
    {
        int err = SSL_get_error(ssl, bytes_read);
        fprintf(stderr, "Failed to read encrypted data with SSL error %d: ", err);
        ERR_print_errors_fp(stderr);
        free(iv);
        free(encrypted_data);
        return;
    }

    FILE *encrypted_file = fopen("encrypted.txt", "wb");
    if (encrypted_file == NULL)
    {
        perror("Failed to open 'encrypted.txt'");
        free(iv);
        free(encrypted_data);
        return;
    }
    fwrite(encrypted_data, 1, bytes_read, encrypted_file);
    fclose(encrypted_file);

    free(iv);
    free(encrypted_data);

    printf("Successfully received and saved IV and encrypted data.\n");
}

int main()
{
    int sock;
    SSL_CTX *ctx;
    SSL *ssl;

    init_openssl();
    ctx = SSL_CTX_new(TLS_client_method());

    if (!ctx)
    {
        perror("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        cleanup_openssl();
        exit(EXIT_FAILURE);
    }

    sock = create_socket();
    ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sock);

    // Perform the SSL handshake
    if (SSL_connect(ssl) != 1)
    {
        ERR_print_errors_fp(stderr);
        SSL_free(ssl);
        close(sock);
        SSL_CTX_free(ctx);
        cleanup_openssl();
        exit(EXIT_FAILURE);
    }

    size_t iv_size = 16;
    size_t encrypted_data_size = 256;

    handle_server(ssl, iv_size, encrypted_data_size);

    SSL_free(ssl);
    close(sock);
    SSL_CTX_free(ctx);
    cleanup_openssl();
}
