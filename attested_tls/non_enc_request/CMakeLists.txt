if (WIN32)
  set(CMAKE_PREFIX_PATH "${CMAKE_PREFIX_PATH};C:\\oe_prereqs\\OpenSSL\\x64\\release")
  find_package(OpenSSL REQUIRED)
else ()
  find_package(OpenSSL REQUIRED)
endif ()

add_executable(tls_non_enc_request request.cpp cert_verify_config.cpp
                                  ../common/verify_callback.cpp)

add_executable(main main.cpp)

add_executable(encryptdata encryptdata.cpp)

add_dependencies(tls_non_enc_request tls_server_sign_enc)

target_include_directories(tls_non_enc_request PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}
                                                       ${CMAKE_CURRENT_BINARY_DIR}
                                                        -I/usr/include/openssl)

target_include_directories(main PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}
                                                        ${CMAKE_CURRENT_BINARY_DIR}
                                                         -I/usr/include/openssl)

target_include_directories(encryptdata PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}
                                                        ${CMAKE_CURRENT_BINARY_DIR}
                                                         -I/usr/include/openssl)

target_link_libraries(tls_non_enc_request openenclave::oehost OpenSSL::SSL)
target_link_libraries(main OpenSSL::SSL OpenSSL::Crypto)
target_link_libraries(encryptdata OpenSSL::SSL OpenSSL::Crypto)

add_dependencies(tls_non_enc_request tls_server)

add_custom_command(
    TARGET main POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy
            ${CMAKE_SOURCE_DIR}/non_enc_request/server.crt
            ${CMAKE_SOURCE_DIR}/non_enc_request/server.key
            $<TARGET_FILE_DIR:main>)
# add_subdirectory(cryptopp-cmake-CRYPTOPP_8_9_0)