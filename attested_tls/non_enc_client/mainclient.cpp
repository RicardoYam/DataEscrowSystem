#include <stdio.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
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

void send_file(SSL* ssl, const char* filename) {
    char buf[1024];
    FILE *file = fopen(filename, "r");
    if (file != NULL) {
        while (fgets(buf, sizeof(buf), file) != NULL) {
            int bytes_written = SSL_write(ssl, buf, strlen(buf));
            if (bytes_written <= 0) {
                fprintf(stderr, "Failed to write to server while sending %s: ", filename);
                ERR_print_errors_fp(stderr);
                break;
            }
        }
        fclose(file);
    } else {
        fprintf(stderr, "Failed to open %s: ", filename);
        perror("");
    }
}

void handle_server(SSL *ssl) {
    char buf[1024] = {0};
    int bytes_read = SSL_read(ssl, buf, sizeof(buf) - 1);
    if (bytes_read <= 0) {
        int err = SSL_get_error(ssl, bytes_read);
        fprintf(stderr, "SSL read failed with error %d: ", err);
        ERR_print_errors_fp(stderr);
        return;
    }

    buf[bytes_read] = '\0';

    if (strcmp(buf, "exchange") == 0) {
        printf("Received 'exchange' from server.\n");
        send_file(ssl, "share1.txt");
        send_file(ssl, "encrypted.txt");
        send_file(ssl, "iv.txt");
    } else {
        printf("Received different message: %s\n", buf);
    }
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

    handle_server(ssl);

    SSL_free(ssl);
    close(sock);
    SSL_CTX_free(ctx);
    cleanup_openssl();
}
