// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.
//
#define ADD_TEST_CHECKING

#define TLS_CLIENT "TLS client: "
#define TLS_SERVER "TLS server: "

#define CLIENT_PAYLOAD "key1"
#define CLIENT_PAYLOAD2 "key2"
#define CONNECTION_DONE "Success"
#define UNSEAL "unseal"
#define SERVER_PAYLOAD                                   \
    "HTTP/1.0 200 OK\r\nContent-Type: text/html\r\n\r\n" \
    "<h2>mbed TLS Test Server</h2>\r\n"                  \
    "<p>Successful connection : </p>\r\n"                \
    "A message from TLS server inside enclave\r\n"

#define CLIENT_PAYLOAD_SIZE strlen(CLIENT_PAYLOAD)
#define CLIENT_PAYLOAD2_SIZE strlen(CLIENT_PAYLOAD2)
#define SERVER_PAYLOAD_SIZE strlen(SERVER_PAYLOAD)
#define CONNECTION_DONE_SIZE strlen(CONNECTION_DONE)
#define UNSEAL_SIZE strlen(UNSEAL)
