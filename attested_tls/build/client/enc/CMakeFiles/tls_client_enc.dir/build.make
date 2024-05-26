# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.16

# Delete rule output on recipe failure.
.DELETE_ON_ERROR:


#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:


# Remove some rules from gmake that .SUFFIXES does not remove.
SUFFIXES =

.SUFFIXES: .hpux_make_needs_suffix_list


# Suppress display of executed commands.
$(VERBOSE).SILENT:


# A target that is always out of date.
cmake_force:

.PHONY : cmake_force

#=============================================================================
# Set environment variables for the build.

# The shell in which to execute make rules.
SHELL = /bin/sh

# The CMake executable.
CMAKE_COMMAND = /usr/bin/cmake

# The command to remove a file.
RM = /usr/bin/cmake -E remove -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /home/azureuser/testSample/attested_tls

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /home/azureuser/testSample/attested_tls/build

# Include any dependencies generated for this target.
include client/enc/CMakeFiles/tls_client_enc.dir/depend.make

# Include the progress variables for this target.
include client/enc/CMakeFiles/tls_client_enc.dir/progress.make

# Include the compile flags for this target's objects.
include client/enc/CMakeFiles/tls_client_enc.dir/flags.make

client/enc/tls_client_t.h: ../client/tls_client.edl
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --blue --bold --progress-dir=/home/azureuser/testSample/attested_tls/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Generating tls_client_t.h, tls_client_t.c, tls_client_args.h"
	cd /home/azureuser/testSample/attested_tls/build/client/enc && /opt/openenclave/bin/oeedger8r --trusted /home/azureuser/testSample/attested_tls/client/tls_client.edl --search-path /opt/openenclave/include --search-path /opt/openenclave/include/openenclave/edl/sgx

client/enc/tls_client_t.c: client/enc/tls_client_t.h
	@$(CMAKE_COMMAND) -E touch_nocreate client/enc/tls_client_t.c

client/enc/tls_client_args.h: client/enc/tls_client_t.h
	@$(CMAKE_COMMAND) -E touch_nocreate client/enc/tls_client_args.h

client/enc/CMakeFiles/tls_client_enc.dir/ecalls.cpp.o: client/enc/CMakeFiles/tls_client_enc.dir/flags.make
client/enc/CMakeFiles/tls_client_enc.dir/ecalls.cpp.o: ../client/enc/ecalls.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/azureuser/testSample/attested_tls/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Building CXX object client/enc/CMakeFiles/tls_client_enc.dir/ecalls.cpp.o"
	cd /home/azureuser/testSample/attested_tls/build/client/enc && /usr/bin/clang++-11  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/tls_client_enc.dir/ecalls.cpp.o -c /home/azureuser/testSample/attested_tls/client/enc/ecalls.cpp

client/enc/CMakeFiles/tls_client_enc.dir/ecalls.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/tls_client_enc.dir/ecalls.cpp.i"
	cd /home/azureuser/testSample/attested_tls/build/client/enc && /usr/bin/clang++-11 $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/azureuser/testSample/attested_tls/client/enc/ecalls.cpp > CMakeFiles/tls_client_enc.dir/ecalls.cpp.i

client/enc/CMakeFiles/tls_client_enc.dir/ecalls.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/tls_client_enc.dir/ecalls.cpp.s"
	cd /home/azureuser/testSample/attested_tls/build/client/enc && /usr/bin/clang++-11 $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/azureuser/testSample/attested_tls/client/enc/ecalls.cpp -o CMakeFiles/tls_client_enc.dir/ecalls.cpp.s

client/enc/CMakeFiles/tls_client_enc.dir/openssl_client.cpp.o: client/enc/CMakeFiles/tls_client_enc.dir/flags.make
client/enc/CMakeFiles/tls_client_enc.dir/openssl_client.cpp.o: ../client/enc/openssl_client.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/azureuser/testSample/attested_tls/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_3) "Building CXX object client/enc/CMakeFiles/tls_client_enc.dir/openssl_client.cpp.o"
	cd /home/azureuser/testSample/attested_tls/build/client/enc && /usr/bin/clang++-11  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/tls_client_enc.dir/openssl_client.cpp.o -c /home/azureuser/testSample/attested_tls/client/enc/openssl_client.cpp

client/enc/CMakeFiles/tls_client_enc.dir/openssl_client.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/tls_client_enc.dir/openssl_client.cpp.i"
	cd /home/azureuser/testSample/attested_tls/build/client/enc && /usr/bin/clang++-11 $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/azureuser/testSample/attested_tls/client/enc/openssl_client.cpp > CMakeFiles/tls_client_enc.dir/openssl_client.cpp.i

client/enc/CMakeFiles/tls_client_enc.dir/openssl_client.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/tls_client_enc.dir/openssl_client.cpp.s"
	cd /home/azureuser/testSample/attested_tls/build/client/enc && /usr/bin/clang++-11 $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/azureuser/testSample/attested_tls/client/enc/openssl_client.cpp -o CMakeFiles/tls_client_enc.dir/openssl_client.cpp.s

client/enc/CMakeFiles/tls_client_enc.dir/cert_verify_config.cpp.o: client/enc/CMakeFiles/tls_client_enc.dir/flags.make
client/enc/CMakeFiles/tls_client_enc.dir/cert_verify_config.cpp.o: ../client/enc/cert_verify_config.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/azureuser/testSample/attested_tls/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_4) "Building CXX object client/enc/CMakeFiles/tls_client_enc.dir/cert_verify_config.cpp.o"
	cd /home/azureuser/testSample/attested_tls/build/client/enc && /usr/bin/clang++-11  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/tls_client_enc.dir/cert_verify_config.cpp.o -c /home/azureuser/testSample/attested_tls/client/enc/cert_verify_config.cpp

client/enc/CMakeFiles/tls_client_enc.dir/cert_verify_config.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/tls_client_enc.dir/cert_verify_config.cpp.i"
	cd /home/azureuser/testSample/attested_tls/build/client/enc && /usr/bin/clang++-11 $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/azureuser/testSample/attested_tls/client/enc/cert_verify_config.cpp > CMakeFiles/tls_client_enc.dir/cert_verify_config.cpp.i

client/enc/CMakeFiles/tls_client_enc.dir/cert_verify_config.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/tls_client_enc.dir/cert_verify_config.cpp.s"
	cd /home/azureuser/testSample/attested_tls/build/client/enc && /usr/bin/clang++-11 $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/azureuser/testSample/attested_tls/client/enc/cert_verify_config.cpp -o CMakeFiles/tls_client_enc.dir/cert_verify_config.cpp.s

client/enc/CMakeFiles/tls_client_enc.dir/__/__/common/verify_callback.cpp.o: client/enc/CMakeFiles/tls_client_enc.dir/flags.make
client/enc/CMakeFiles/tls_client_enc.dir/__/__/common/verify_callback.cpp.o: ../common/verify_callback.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/azureuser/testSample/attested_tls/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_5) "Building CXX object client/enc/CMakeFiles/tls_client_enc.dir/__/__/common/verify_callback.cpp.o"
	cd /home/azureuser/testSample/attested_tls/build/client/enc && /usr/bin/clang++-11  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/tls_client_enc.dir/__/__/common/verify_callback.cpp.o -c /home/azureuser/testSample/attested_tls/common/verify_callback.cpp

client/enc/CMakeFiles/tls_client_enc.dir/__/__/common/verify_callback.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/tls_client_enc.dir/__/__/common/verify_callback.cpp.i"
	cd /home/azureuser/testSample/attested_tls/build/client/enc && /usr/bin/clang++-11 $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/azureuser/testSample/attested_tls/common/verify_callback.cpp > CMakeFiles/tls_client_enc.dir/__/__/common/verify_callback.cpp.i

client/enc/CMakeFiles/tls_client_enc.dir/__/__/common/verify_callback.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/tls_client_enc.dir/__/__/common/verify_callback.cpp.s"
	cd /home/azureuser/testSample/attested_tls/build/client/enc && /usr/bin/clang++-11 $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/azureuser/testSample/attested_tls/common/verify_callback.cpp -o CMakeFiles/tls_client_enc.dir/__/__/common/verify_callback.cpp.s

client/enc/CMakeFiles/tls_client_enc.dir/__/__/common/utility.cpp.o: client/enc/CMakeFiles/tls_client_enc.dir/flags.make
client/enc/CMakeFiles/tls_client_enc.dir/__/__/common/utility.cpp.o: ../common/utility.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/azureuser/testSample/attested_tls/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_6) "Building CXX object client/enc/CMakeFiles/tls_client_enc.dir/__/__/common/utility.cpp.o"
	cd /home/azureuser/testSample/attested_tls/build/client/enc && /usr/bin/clang++-11  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/tls_client_enc.dir/__/__/common/utility.cpp.o -c /home/azureuser/testSample/attested_tls/common/utility.cpp

client/enc/CMakeFiles/tls_client_enc.dir/__/__/common/utility.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/tls_client_enc.dir/__/__/common/utility.cpp.i"
	cd /home/azureuser/testSample/attested_tls/build/client/enc && /usr/bin/clang++-11 $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/azureuser/testSample/attested_tls/common/utility.cpp > CMakeFiles/tls_client_enc.dir/__/__/common/utility.cpp.i

client/enc/CMakeFiles/tls_client_enc.dir/__/__/common/utility.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/tls_client_enc.dir/__/__/common/utility.cpp.s"
	cd /home/azureuser/testSample/attested_tls/build/client/enc && /usr/bin/clang++-11 $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/azureuser/testSample/attested_tls/common/utility.cpp -o CMakeFiles/tls_client_enc.dir/__/__/common/utility.cpp.s

client/enc/CMakeFiles/tls_client_enc.dir/__/__/common/openssl_utility.cpp.o: client/enc/CMakeFiles/tls_client_enc.dir/flags.make
client/enc/CMakeFiles/tls_client_enc.dir/__/__/common/openssl_utility.cpp.o: ../common/openssl_utility.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/azureuser/testSample/attested_tls/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_7) "Building CXX object client/enc/CMakeFiles/tls_client_enc.dir/__/__/common/openssl_utility.cpp.o"
	cd /home/azureuser/testSample/attested_tls/build/client/enc && /usr/bin/clang++-11  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/tls_client_enc.dir/__/__/common/openssl_utility.cpp.o -c /home/azureuser/testSample/attested_tls/common/openssl_utility.cpp

client/enc/CMakeFiles/tls_client_enc.dir/__/__/common/openssl_utility.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/tls_client_enc.dir/__/__/common/openssl_utility.cpp.i"
	cd /home/azureuser/testSample/attested_tls/build/client/enc && /usr/bin/clang++-11 $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/azureuser/testSample/attested_tls/common/openssl_utility.cpp > CMakeFiles/tls_client_enc.dir/__/__/common/openssl_utility.cpp.i

client/enc/CMakeFiles/tls_client_enc.dir/__/__/common/openssl_utility.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/tls_client_enc.dir/__/__/common/openssl_utility.cpp.s"
	cd /home/azureuser/testSample/attested_tls/build/client/enc && /usr/bin/clang++-11 $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/azureuser/testSample/attested_tls/common/openssl_utility.cpp -o CMakeFiles/tls_client_enc.dir/__/__/common/openssl_utility.cpp.s

client/enc/CMakeFiles/tls_client_enc.dir/tls_client_t.c.o: client/enc/CMakeFiles/tls_client_enc.dir/flags.make
client/enc/CMakeFiles/tls_client_enc.dir/tls_client_t.c.o: client/enc/tls_client_t.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/azureuser/testSample/attested_tls/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_8) "Building C object client/enc/CMakeFiles/tls_client_enc.dir/tls_client_t.c.o"
	cd /home/azureuser/testSample/attested_tls/build/client/enc && /usr/bin/clang-11 $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/tls_client_enc.dir/tls_client_t.c.o   -c /home/azureuser/testSample/attested_tls/build/client/enc/tls_client_t.c

client/enc/CMakeFiles/tls_client_enc.dir/tls_client_t.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/tls_client_enc.dir/tls_client_t.c.i"
	cd /home/azureuser/testSample/attested_tls/build/client/enc && /usr/bin/clang-11 $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/azureuser/testSample/attested_tls/build/client/enc/tls_client_t.c > CMakeFiles/tls_client_enc.dir/tls_client_t.c.i

client/enc/CMakeFiles/tls_client_enc.dir/tls_client_t.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/tls_client_enc.dir/tls_client_t.c.s"
	cd /home/azureuser/testSample/attested_tls/build/client/enc && /usr/bin/clang-11 $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/azureuser/testSample/attested_tls/build/client/enc/tls_client_t.c -o CMakeFiles/tls_client_enc.dir/tls_client_t.c.s

# Object files for target tls_client_enc
tls_client_enc_OBJECTS = \
"CMakeFiles/tls_client_enc.dir/ecalls.cpp.o" \
"CMakeFiles/tls_client_enc.dir/openssl_client.cpp.o" \
"CMakeFiles/tls_client_enc.dir/cert_verify_config.cpp.o" \
"CMakeFiles/tls_client_enc.dir/__/__/common/verify_callback.cpp.o" \
"CMakeFiles/tls_client_enc.dir/__/__/common/utility.cpp.o" \
"CMakeFiles/tls_client_enc.dir/__/__/common/openssl_utility.cpp.o" \
"CMakeFiles/tls_client_enc.dir/tls_client_t.c.o"

# External object files for target tls_client_enc
tls_client_enc_EXTERNAL_OBJECTS =

client/enc/tls_client_enc: client/enc/CMakeFiles/tls_client_enc.dir/ecalls.cpp.o
client/enc/tls_client_enc: client/enc/CMakeFiles/tls_client_enc.dir/openssl_client.cpp.o
client/enc/tls_client_enc: client/enc/CMakeFiles/tls_client_enc.dir/cert_verify_config.cpp.o
client/enc/tls_client_enc: client/enc/CMakeFiles/tls_client_enc.dir/__/__/common/verify_callback.cpp.o
client/enc/tls_client_enc: client/enc/CMakeFiles/tls_client_enc.dir/__/__/common/utility.cpp.o
client/enc/tls_client_enc: client/enc/CMakeFiles/tls_client_enc.dir/__/__/common/openssl_utility.cpp.o
client/enc/tls_client_enc: client/enc/CMakeFiles/tls_client_enc.dir/tls_client_t.c.o
client/enc/tls_client_enc: client/enc/CMakeFiles/tls_client_enc.dir/build.make
client/enc/tls_client_enc: /opt/openenclave/lib/openenclave/enclave/liboeenclave.a
client/enc/tls_client_enc: /opt/openenclave/lib/openenclave/enclave/liboecryptoopenssl.a
client/enc/tls_client_enc: /opt/openenclave/lib/openenclave/enclave/liboelibcxx.a
client/enc/tls_client_enc: /opt/openenclave/lib/openenclave/enclave/liboehostsock.a
client/enc/tls_client_enc: /opt/openenclave/lib/openenclave/enclave/liboehostresolver.a
client/enc/tls_client_enc: /opt/openenclave/lib/openenclave/enclave/libopensslssl.a
client/enc/tls_client_enc: /opt/openenclave/lib/openenclave/enclave/libopensslcrypto.a
client/enc/tls_client_enc: /opt/openenclave/lib/openenclave/enclave/liboelibc.a
client/enc/tls_client_enc: /opt/openenclave/lib/openenclave/enclave/liboesyscall.a
client/enc/tls_client_enc: /opt/openenclave/lib/openenclave/enclave/liboecore.a
client/enc/tls_client_enc: client/enc/CMakeFiles/tls_client_enc.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/home/azureuser/testSample/attested_tls/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_9) "Linking CXX executable tls_client_enc"
	cd /home/azureuser/testSample/attested_tls/build/client/enc && $(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/tls_client_enc.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
client/enc/CMakeFiles/tls_client_enc.dir/build: client/enc/tls_client_enc

.PHONY : client/enc/CMakeFiles/tls_client_enc.dir/build

client/enc/CMakeFiles/tls_client_enc.dir/clean:
	cd /home/azureuser/testSample/attested_tls/build/client/enc && $(CMAKE_COMMAND) -P CMakeFiles/tls_client_enc.dir/cmake_clean.cmake
.PHONY : client/enc/CMakeFiles/tls_client_enc.dir/clean

client/enc/CMakeFiles/tls_client_enc.dir/depend: client/enc/tls_client_t.h
client/enc/CMakeFiles/tls_client_enc.dir/depend: client/enc/tls_client_t.c
client/enc/CMakeFiles/tls_client_enc.dir/depend: client/enc/tls_client_args.h
	cd /home/azureuser/testSample/attested_tls/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/azureuser/testSample/attested_tls /home/azureuser/testSample/attested_tls/client/enc /home/azureuser/testSample/attested_tls/build /home/azureuser/testSample/attested_tls/build/client/enc /home/azureuser/testSample/attested_tls/build/client/enc/CMakeFiles/tls_client_enc.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : client/enc/CMakeFiles/tls_client_enc.dir/depend

