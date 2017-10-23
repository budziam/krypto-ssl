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

unsigned char init_vector[BF_BLOCK] = {0, 1, 2, 3, 4, 5, 6, 7};

void diedie(char *message) {
    printf("%s\n", message);
    exit(1);
}

void prepare_blowfish_key(char *cipher) {
    BF_set_key(&bf_key, 8, (const unsigned char *) cipher);
}

void open_files(char **argv) {
    if ((input_file = fopen(argv[3], "rb")) == NULL) {
        diedie("cannot read input file");
    }

    if ((output_file = fopen(argv[4], "wb")) == NULL) {
        diedie("cannot read output file");
    }
}


void close_files() {
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

void bf_crypt(unsigned char *input_block, unsigned char *output_block, const int encryption_mode) {
    if (ECB == chaining_mode) {
        BF_ecb_encrypt(input_block, output_block, &bf_key, encryption_mode);
    } else {
        BF_cbc_encrypt(input_block, output_block, BF_BLOCK, &bf_key, init_vector, encryption_mode);
    }
}

void encrypt_block(unsigned char *input_block, unsigned char *output_block) {
    bf_crypt(input_block, output_block, BF_ENCRYPT);
}

void copy_buffer(unsigned char *from, unsigned char *to) {
    int i;
    for (i = 0; i < BF_BLOCK; ++i) {
        to[i] = from[i];
    }
}

void handle_encrypt_block(unsigned char *encryption_target_block, unsigned char *encrypted_block,
                          unsigned char *rewrite_target_block) {
    encrypt_block(encryption_target_block, encrypted_block);
    copy_buffer(encryption_target_block, rewrite_target_block);
}

void write_buffer_to_file(unsigned char *buffer) {
    fwrite(buffer, BF_BLOCK, 1, output_file);
}

void clear_buffer(unsigned char *buffer) {
    int i;
    for (i = 0; i < BF_BLOCK; ++i) {
        buffer[i] = 0;
    }
}

void add_iso_10216_2_padding(unsigned char *block, int last_block_size) {
    int i;
    for (i = last_block_size; i < BF_BLOCK; ++i) {
        block[i] = 1;
    }

    block[BF_BLOCK - 1] = BF_BLOCK - last_block_size;
}

void encrypt_file() {
    int bytes_read;
    unsigned char encryption_target_block[BF_BLOCK];
    unsigned char encrypted_block[BF_BLOCK];
    unsigned char previous_encrypted_block[BF_BLOCK];

    bytes_read = (int) fread(encryption_target_block, 1, BF_BLOCK, input_file);
    while (bytes_read == BF_BLOCK) {
        handle_encrypt_block(encryption_target_block, encrypted_block, previous_encrypted_block);

        write_buffer_to_file(encrypted_block);

        clear_buffer(encryption_target_block);
        bytes_read = (int) fread(encryption_target_block, 1, BF_BLOCK, input_file);
    }

    add_iso_10216_2_padding(encryption_target_block, bytes_read);

    encrypt_block(encryption_target_block, encrypted_block);
    write_buffer_to_file(encrypted_block);
}

void write_previous_decrypted_block(unsigned char *decrypted_block, unsigned char *rewrite_target_block) {
    write_buffer_to_file(decrypted_block);
    copy_buffer(decrypted_block, rewrite_target_block);
}


void decrypt_block(unsigned char *input_block, unsigned char *output_block) {
    bf_crypt(input_block, output_block, BF_DECRYPT);
}

void handle_decrypt_block(unsigned char *encrypted_block, unsigned char *decrypted_block,
                          unsigned char *rewrite_target_block) {
    decrypt_block(encrypted_block, decrypted_block);
    copy_buffer(decrypted_block, rewrite_target_block);
}

void remove_iso_10216_2_padding(unsigned char *block) {
    int size = block[BF_BLOCK - 1];

    int i;
    for (i = BF_BLOCK - 1; i > BF_BLOCK - 1 - size; --i) {
        block[i] = 0;
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

    remove_iso_10216_2_padding(previous_decrypted_block);
    write_buffer_to_file(previous_decrypted_block);
}


void blowfish_crypt_file() {
    if (BF_ENCRYPT == encryption_mode) {
        encrypt_file();
    } else if (BF_DECRYPT == encryption_mode) {
        decrypt_file();
    } else {
        diedie("Wrong encryption mode");
    }
}

int main(int argc, char **argv) {
    handle_arguments(argc, argv);
    open_files(argv);
    prepare_blowfish_key(argv[5]);
    blowfish_crypt_file(encryption_mode);
    close_files();
}
