#include <stdio.h>
#include <openssl/blowfish.h>
#include <string.h>
#include <stdlib.h>

const int CBC = 0;
const int ECB = 1;
int chaining_mode;
int encryption_mode;

void diedie(char * message) {
    printf("%s\n", message);
    exit(1);
}

void prepare_blowfish_key(char *cipher) {
    if (BF_ENCRYPT == encryption_mode) {
//        AES_set_encrypt_key((const unsigned char *) cipher, AES_BLOCK_SIZE * 8, &aes_key);
    }
    else if (BF_DECRYPT == encryption_mode) {
//        AES_set_decrypt_key((const unsigned char *) cipher, AES_BLOCK_SIZE * 8, &aes_key);
    }
    else {
        diedie("No encryption mode");
    }
}

void handle_arguments(int argc, char **argv) {
    if (argc != 6) {
        diedie("Use: [-enc|-dec] [-ecb|-cbc] input_path output_path cipher");
    }

    if (strcmp(argv[1], "-enc") == 0) {
        encryption_mode = BF_ENCRYPT;
    } else if (strcmp(argv[1], "-dec") == 0) {
        encryption_mode = BF_DECRYPT;
    } else {
        diedie("No enc/dec");
    }

    if (strcmp(argv[2], "-cbc") == 0) {
        chaining_mode = CBC;
    } else if (strcmp(argv[2], "-ecb") == 0) {
        chaining_mode = ECB;
    } else {
        diedie("No cbc/ecb");
    }
}

int main(int argc, char** argv) {
    handle_arguments(argc, argv);
//    open_files(argv);
//    prepare_aes_key(argv[5]);
//    aes_crypt_file(encryption_mode);
//    close_files();
}
