#include <stdio.h>
#include <openssl/aes.h>
#include <string.h>

#define ERROR -1
#define SUCCESS 0

const int CBC = 0;
const int ECB = 1;
int chaining_mode;
int encryption_mode;
FILE *input_file;
FILE *output_file;
AES_KEY aes_key;
unsigned char init_vector[AES_BLOCK_SIZE] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};

int decrypt_file();
int encrypt_file();
int copy_buffer(unsigned char *from, unsigned char *to);
int clear_buffer(unsigned char *buffer);
int write_buffer_to_file(unsigned char *buffer);
int encrypt_block(unsigned char *input_block, unsigned char *output_block);
int decrypt_block(unsigned char *input_block, unsigned char *output_block);
int aes_crypt(unsigned char *input_block, unsigned char *output_block, const int encryption_mode);
int handle_arguments(int argc, char **argv);
int open_files(char **pString);
int close_files();
int prepare_aes_key(char *user_key);
int aes_crypt_file(int encryption_mode);
int retrieve_stolen_cipher_text(unsigned char *thief, unsigned char *owner);
int cipher_text_steal(unsigned char *thief, unsigned char *owner, int steal_start);
int handle_decrypt_block(unsigned char *encrypted_block, unsigned char *decrypted_block, unsigned char *rewrite_target_block);
int handle_encrypt_block(unsigned char *encryption_target_block, unsigned char *encrypted_block, unsigned char *rewrite_target_block);
int write_previous_decrypted_block(unsigned char *decrypted_block, unsigned char *rewrite_target_block);

int main(int argc, char** argv) {
    handle_arguments(argc, argv);
    open_files(argv);
    prepare_aes_key(argv[5]);
    aes_crypt_file(encryption_mode);
    close_files();

    return SUCCESS;
}

int encrypt_file() {
    int bytes_read;
    unsigned char encryption_target_block[AES_BLOCK_SIZE];
    unsigned char encrypted_block[AES_BLOCK_SIZE];
    unsigned char previous_encrypted_block[AES_BLOCK_SIZE];

    bytes_read = (int) fread(encryption_target_block, 1, AES_BLOCK_SIZE, input_file);
    while (bytes_read == AES_BLOCK_SIZE) {
        handle_encrypt_block(encryption_target_block, encrypted_block, previous_encrypted_block);

        write_buffer_to_file(encrypted_block);

        clear_buffer(encryption_target_block);
        bytes_read = (int) fread(encryption_target_block, 1, AES_BLOCK_SIZE, input_file);
    }

    cipher_text_steal(encryption_target_block, previous_encrypted_block, bytes_read);

    encrypt_block(encryption_target_block, encrypted_block);
    write_buffer_to_file(encrypted_block);

    return SUCCESS;
}

int handle_encrypt_block(unsigned char *encryption_target_block, unsigned char *encrypted_block, unsigned char *rewrite_target_block) {
    encrypt_block(encryption_target_block, encrypted_block);
    copy_buffer(encryption_target_block, rewrite_target_block);

    return SUCCESS;
}

int decrypt_file() {
    int bytes_read;
    unsigned char encrypted_block[AES_BLOCK_SIZE];
    unsigned char decrypted_block[AES_BLOCK_SIZE];
    unsigned char previous_decrypted_block[AES_BLOCK_SIZE];
    unsigned char second_previous_decrypted_block[AES_BLOCK_SIZE];

    fread(encrypted_block, 1, AES_BLOCK_SIZE, input_file);
    handle_decrypt_block(encrypted_block, decrypted_block, previous_decrypted_block);

    bytes_read = (int) fread(encrypted_block, 1, AES_BLOCK_SIZE, input_file);
    while (bytes_read == AES_BLOCK_SIZE) {
        write_previous_decrypted_block(previous_decrypted_block, second_previous_decrypted_block);

        handle_decrypt_block(encrypted_block, decrypted_block, previous_decrypted_block);

        bytes_read = (int) fread(encrypted_block, 1, AES_BLOCK_SIZE, input_file);
    }

    if (bytes_read != 0) {
        fprintf(stderr, "This should not happen in decryption mode.");
        fprintf(stderr, "Encrypted input file should have blocks of equal size.\n");

        return ERROR;
    }

    retrieve_stolen_cipher_text(previous_decrypted_block, second_previous_decrypted_block);
    write_buffer_to_file(previous_decrypted_block);

    return SUCCESS;
}

int write_previous_decrypted_block(unsigned char *decrypted_block, unsigned char *rewrite_target_block) {
    write_buffer_to_file(decrypted_block);
    copy_buffer(decrypted_block, rewrite_target_block);

    return SUCCESS;
}

int handle_decrypt_block(unsigned char *encrypted_block, unsigned char *decrypted_block, unsigned char *rewrite_target_block) {
    decrypt_block(encrypted_block, decrypted_block);
    copy_buffer(decrypted_block, rewrite_target_block);

    return SUCCESS;
}

int aes_crypt_file(int encryption_mode) {
    if (AES_ENCRYPT == encryption_mode) {
        return encrypt_file();
    } else if (AES_DECRYPT == encryption_mode) {
        return decrypt_file();
    }

    return ERROR;
}

int prepare_aes_key(char *user_key) {
    if (AES_ENCRYPT == encryption_mode) {
        AES_set_encrypt_key((const unsigned char *) user_key, AES_BLOCK_SIZE * 8, &aes_key);
    }
    if (AES_DECRYPT == encryption_mode) {
        AES_set_decrypt_key((const unsigned char *) user_key, AES_BLOCK_SIZE * 8, &aes_key);
    }

    return SUCCESS;
}

int open_files(char **argv) {
    if ((input_file = fopen(argv[3], "rb")) == NULL) {
        fprintf(stderr, "%s: can not read input file %s\n", argv[0], argv[3]);
        return ERROR;
    }

    if ((output_file = fopen(argv[4], "wb")) == NULL) {
        fprintf(stderr, "%s: can not read output file %s\n", argv[0], argv[3]);
        return ERROR;
    }

    return SUCCESS;
}

int close_files()
{
    fclose(input_file);
    fflush(output_file);
    fclose(output_file);

    return SUCCESS;
}

int handle_arguments(int argc, char **argv) {
    if (argc != 6) {
        fprintf(stderr, "Use: -enc|-dec -ecb|-cbc input_file_path output_file_path cipher");
        return ERROR;
    }

    if (strcmp(argv[1], "-enc") == 0) {
        encryption_mode = AES_ENCRYPT;
    } else if (strcmp(argv[1], "-dec") == 0) {
        encryption_mode = AES_DECRYPT;
    } else {
        return ERROR;
    }

    if (strcmp(argv[2], "-cbc") == 0) {
        chaining_mode = CBC;
    } else if (strcmp(argv[2], "-ecb") == 0) {
        chaining_mode = ECB;
    } else {
        return ERROR;
    }

    return SUCCESS;
}

int retrieve_stolen_cipher_text(unsigned char *thief, unsigned char *owner) {
    for (int i = AES_BLOCK_SIZE - 1; i >= 0; --i) {
        if (owner[i] == thief[i]) {
            thief[i] = 0;
        } else {
            return SUCCESS;
        }
    }

    return SUCCESS;
}

int cipher_text_steal(unsigned char *thief, unsigned char *owner, int steal_start) {
    for (int i = steal_start; i < AES_BLOCK_SIZE; ++i) {
        thief[i] = owner[i];
    }

    return SUCCESS;
}

int encrypt_block(unsigned char *input_block, unsigned char *output_block) {
    return aes_crypt(input_block, output_block, AES_ENCRYPT);
}

int decrypt_block(unsigned char *input_block, unsigned char *output_block) {
    return aes_crypt(input_block, output_block, AES_DECRYPT);
}

int aes_crypt(unsigned char *input_block, unsigned char *output_block, const int encryption_mode) {
    if (ECB == chaining_mode) {
        AES_ecb_encrypt(input_block, output_block, &aes_key, encryption_mode);
    } else {
        AES_cbc_encrypt(input_block, output_block, AES_BLOCK_SIZE, &aes_key, init_vector, encryption_mode);
    }

    return SUCCESS;
}

int write_buffer_to_file(unsigned char *buffer) {
    return (int) fwrite(buffer, AES_BLOCK_SIZE, 1, output_file);
}

int copy_buffer(unsigned char *from, unsigned char *to) {
    for (int i = 0; i < AES_BLOCK_SIZE; ++i) {
        to[i] = from[i];
    }

    return SUCCESS;
}

int clear_buffer(unsigned char *buffer) {
    for (int i = 0; i < AES_BLOCK_SIZE; ++i) {
        buffer[i] = 0;
    }

    return SUCCESS;
}