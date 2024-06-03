#include <openenclave/host.h>
#include <stdio.h>
#include "tls_server_u.h"
#include "crow.h"
#include "crow/middlewares/cors.h"
#include <unistd.h>
#include <time.h>

static char *publicHex = NULL;

void host_getPublicKey(char *msg)
{
    if (publicHex != NULL)
    {
        free(publicHex);
        publicHex = NULL;
    }

    if (msg != NULL)
    {
        publicHex = (char *)malloc(strlen(msg) + 1);
        if (publicHex != NULL)
        {
            strcpy(publicHex, msg);
        }
    }
}

oe_enclave_t *create_enclave(const char *enclave_path)
{
    oe_enclave_t *enclave = NULL;

    printf("Host: Enclave library %s\n", enclave_path);
    oe_result_t result = oe_create_tls_server_enclave(
        enclave_path,
        OE_ENCLAVE_TYPE_SGX,
        OE_ENCLAVE_FLAG_DEBUG,
        NULL,
        0,
        &enclave);

    if (result != OE_OK)
    {
        printf(
            "Host: oe_create_remoteattestation_enclave failed. %s",
            oe_result_str(result));
    }
    else
    {
        printf("Host: Enclave successfully created.\n");
    }
    return enclave;
}

void terminate_enclave(oe_enclave_t *enclave)
{
    oe_terminate_enclave(enclave);
    printf("Host: Enclave successfully terminated.\n");
}

int main(int argc, const char *argv[])
{
    oe_enclave_t *enclave = NULL;
    oe_result_t result = OE_OK;
    int ret = 1;
    char *server_port = NULL;
    bool keep_server_up = false;
    uint8_t *sealed_blob = NULL;
    size_t sealed_size = 0;
    char uuid_str[37];

    clock_t start, end;
    double time_used;

    /* Check argument count */
    if (argc == 3)
    {
        keep_server_up = true;
        goto read_port;
    }
    else
    {
        printf("Arguments error");
    }

read_port:
    // read port parameter
    {
        char *port_prefix = (char *)"-port:";
        size_t port_prefix_len = strlen(port_prefix);

        if (strncmp(argv[2], port_prefix, port_prefix_len) == 0)
        {
            server_port = (char *)(argv[2] + port_prefix_len);
        }
    }
    printf("Server port = %s\n", server_port);

    printf("Host: Creating an tls client enclave\n");

    enclave = create_enclave(argv[1]);
    if (enclave == NULL)
    {
        return 1;
    }

    // while (1) {
    //     generate_keypair(enclave, &sealed_blob, &sealed_size);
    //     unseal_data(enclave, sealed_blob, sealed_size);
    //     sleep(1);
    // }

    printf("Host: set TLS preperation\n");
    ret = set_up_tls_server(enclave, &ret, server_port, uuid_str);
    printf("\noutside_uuid_sgx_ecdsa: %s\n", uuid_str);

    start = clock(); 
    ret = handle_communication_until_done(enclave, &ret, false, NULL);
    end = clock();  
    
    time_used = ((double) (end - start)) / CLOCKS_PER_SEC * 1000;
    printf("Time taken: %f ms\n", time_used);

    // Receive request
    crow::App<crow::CORSHandler> app;

    auto &cors = app.get_middleware<crow::CORSHandler>();

    cors.global()
        .origin("*")
        .headers("Content-Type, Accept")
        .methods("POST"_method, "GET"_method);

    CROW_ROUTE(app, "/data").methods("POST"_method)([&](const crow::request &req)
                                                    {
        auto x = crow::json::load(req.body);
        if (!x) return crow::response(400, "Invalid JSON");

        std::string dataId;
        if (x.has("dataId")) {
            dataId = x["dataId"].s();

            char* temp = new char[dataId.size() + 1];
            std::strcpy(temp, dataId.c_str());

            generate_keypair(enclave, &sealed_blob, &sealed_size);

            enclave_getPublicKey(enclave);

            ret = handle_communication_until_done(enclave, &ret, false, NULL);

            ret = handle_communication_until_done(enclave, &ret, false, temp);

            ret = handle_communication_until_done(enclave, &ret, false, NULL);

            delete[] temp;
        } else {
            return crow::response(400, "Missing dataId");
        }

        crow::json::wvalue response;
        response["message"] = "Data ID and share received";
        response["quoteRA"] = uuid_str;
        response["pkd"] = publicHex;
        
        return crow::response{200, response}; });

    CROW_ROUTE(app, "/access").methods("POST"_method)([&](const crow::request &req)
                                                      {
        auto x = crow::json::load(req.body);
        if (!x) return crow::response(400, "Invalid JSON");

        if (!x.has("blockhash"))
            return crow::response(400, "Missing blockhash");

        std::string blockhash = x["blockhash"].s();

        try {
            unseal_data(enclave, sealed_blob, sealed_size);
            
            const char* temp = "unseal";

            ret = handle_communication_until_done(enclave, &ret, false, (char *)temp);
        } catch (const std::exception& e) {
            return crow::response(500, "Error processing blockhash");
        }

        crow::json::wvalue response;
        response["message"] = "blockhash received";
        response["blockhash"] = blockhash;
        
        return crow::response{200, response}; });

    app.bindaddr("127.0.0.1").port(8080).run();

    free_tls(enclave);

    if (ret != 0)
    {
        printf("Host: setup_tls_server failed\n");
        goto exit;
    }

exit:
    printf("Host: Terminating enclaves\n");
    if (enclave)
        terminate_enclave(enclave);
    return ret;
}
