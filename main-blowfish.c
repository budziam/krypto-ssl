#include <stdio.h>
#include <openssl/blowfish.h>
#include <string.h>
#include <stdlib.h>

const int CBC = 0;
const int ECB = 1;

FILE *input_file;
FILE *output_file;

int chaining_mode;
int encryption_mode;
BF_KEY bf_key;

void diedie(char * message) {
    printf("%s\n", message);
    exit(1);
}

void prepare_blowfish_key(char *cipher) {
    BF_set_key(&bf_key, 8, (const unsigned char *)cipher);
}

void open_files(char **argv) {
    if ((input_file = fopen(argv[3], "rb")) == NULL) {
        diedie("cannot read input file");
    }

    if ((output_file = fopen(argv[4], "wb")) == NULL) {
        diedie("cannot read output file");
    }
}


void close_files()
{
    fclose(input_file);
    fflush(output_file);
    fclose(output_file);
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

void encrypt_file() {

}

int write_buffer_to_file(unsigned char *buffer) {
    return (int) fwrite(buffer, BF_BLOCK, 1, output_file);
}


void write_previous_decrypted_block(unsigned char *decrypted_block, unsigned char *rewrite_target_block) {
    write_buffer_to_file(decrypted_block);
    copy_buffer(decrypted_block, rewrite_target_block);
}


void handle_decrypt_block(unsigned char *encrypted_block, unsigned char *decrypted_block, unsigned char *rewrite_target_block) {
    decrypt_block(encrypted_block, decrypted_block);
    copy_buffer(decrypted_block, rewrite_target_block);
}

void retrieve_stolen_cipher_text(unsigned char *thief, unsigned char *owner) {
    for (int i = BF_BLOCK - 1; i >= 0; --i) {
        if (owner[i] == thief[i]) {
            thief[i] = 0;
        }
    }
}

void decrypt_file() {
    int bytes_read;
    unsigned char encrypted_block[BF_BLOCK];
    unsigned char decrypted_block[BF_BLOCK];
    unsigned char previous_decrypted_block[BF_BLOCK];
    unsigned char second_previous_decrypted_block[BF_BLOCK];

    fread(encrypted_block, 1, BF_BLOCK, input_file);
    handle_decrypt_block(encrypted_block, decrypted_block, previous_decrypted_block);

    bytes_read = (int) fread(encrypted_block, 1, BF_BLOCK, input_file);
    while (bytes_read == BF_BLOCK) {
        write_previous_decrypted_block(previous_decrypted_block, second_previous_decrypted_block);

        handle_decrypt_block(encrypted_block, decrypted_block, previous_decrypted_block);

        bytes_read = (int) fread(encrypted_block, 1, BF_BLOCK, input_file);
    }

    if (bytes_read != 0) {
        fprintf(stderr, "This should not happen in decryption mode.");
        diedie("Encrypted input file should have block of equal size.\n");
    }

    retrieve_stolen_cipher_text(previous_decrypted_block, second_previous_decrypted_block);
    write_buffer_to_file(previous_decrypted_block);
}


void blowfish_crypt_file() {
    if (BF_ENCRYPT == encryption_mode) {
        encrypt_file();
    }
    else if (BF_DECRYPT == encryption_mode) {
        decrypt_file();
    } else {
        diedie("Wrong encryption mode");
    }
}

int main(int argc, char** argv) {
    handle_arguments(argc, argv);
    open_files(argv);
    prepare_blowfish_key(argv[5]);
    blowfish_crypt_file(encryption_mode);
    close_files();
}
