#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/camellia.h>

// https://en.wikipedia.org/wiki/Padding_(cryptography)#ANSI_X.923
// https://github.com/openssl/openssl/blob/master/include/openssl/camellia.h

char prompt[]  = "[input] [output] [camellia_key (at least 16 bytes)] -cbc/ecb -encrypt/decrypt";

int main(int argc, char* argv[]) {
    int cbc;
    int encrypt;
    FILE *input, *output;
    int byte_read;
    unsigned char buffer[CAMELLIA_BLOCK_SIZE];
    unsigned char *key = argv[3];
    CAMELLIA_KEY camellia_key;
    unsigned char out_buffer[CAMELLIA_BLOCK_SIZE];
    int prev_read = 0;
    char n;
    char ivec[CAMELLIA_BLOCK_SIZE];
    memset(ivec, 0, CAMELLIA_BLOCK_SIZE);

    if(argc < 6) {
        puts(prompt);
        return 1;
    }


    input = fopen(argv[1], "rb");
    output = fopen(argv[2], "wb");


    if((input == 0) || (output == 0)) {
        if(input == 0)
            puts("Error reading input file");
        if(output == 0)
            puts("Error reading output file");
        return 4;
    }

    if (strlen(argv[3]) < 16) {
        puts(prompt);
        return 12;
    }

    if(!strcmp(argv[4],"-cbc")) {
        cbc = 1;
    } else if(!strcmp(argv[4],"-ecb")) {
        cbc = 0;
    } else {
        puts(prompt);
        return 2;
    }


    if(!strcmp(argv[5], "-encrypt")) {
        encrypt = CAMELLIA_ENCRYPT;
    } else if(!strcmp(argv[5], "-decrypt")) {
        encrypt = CAMELLIA_DECRYPT;
    } else {
        puts(prompt);
        return 3;
    }


    fprintf(stderr, "Block Size: %d\n", CAMELLIA_BLOCK_SIZE);
    fprintf(stderr, "Setting key = %s\n", key);
    Camellia_set_key(key, 128, &camellia_key);
    fprintf(stderr, "DONE: Setting key\n");


    int block_index = 0;
    while( (byte_read = fread(buffer, 1, CAMELLIA_BLOCK_SIZE, input))) {


        fprintf(stderr, "Processing block %d byte read: %d\n", block_index, byte_read);
        if((encrypt == CAMELLIA_DECRYPT) && prev_read) {
            fprintf(stderr, "Trying to write to out_buffer after decryption\n");
            fwrite(out_buffer, 1, CAMELLIA_BLOCK_SIZE, output);
            fprintf(stderr, "Out_buffer write after decryption \n");
        }

        if((byte_read) < CAMELLIA_BLOCK_SIZE && (encrypt == CAMELLIA_ENCRYPT)) {
            fprintf(stderr, "Doing padding\n");
            n = CAMELLIA_BLOCK_SIZE - byte_read;
            int i = n - 1;
            while(i >= 1) {
                buffer[CAMELLIA_BLOCK_SIZE - 1 - i] = 0;
                i--;
            }
            buffer[CAMELLIA_BLOCK_SIZE - 1] = n;
        }
        else {
            n = 0;
        }

        prev_read = 1;

        fprintf(stderr, "Attempting to encrypt/decrypt block %d\n", block_index);
        if (cbc == 1) {
            //void Camellia_cbc_encrypt(const unsigned char *in, unsigned char *out, size_t length, const CAMELLIA_KEY *key,
            //unsigned char *ivec, const int enc);
            Camellia_cbc_encrypt(buffer, out_buffer, CAMELLIA_BLOCK_SIZE, &camellia_key, ivec, encrypt);
        } else {
            //void Camellia_ecb_encrypt(const unsigned char *in, unsigned char *out, const CAMELLIA_KEY *key, const int enc);
            Camellia_ecb_encrypt(buffer, out_buffer, &camellia_key, encrypt);
        }

        if (encrypt == CAMELLIA_ENCRYPT) {
            fwrite(out_buffer, 1, CAMELLIA_BLOCK_SIZE, output);
        }
        block_index++;
    }

    if (encrypt == CAMELLIA_DECRYPT) {
        int out_count = CAMELLIA_BLOCK_SIZE - out_buffer[CAMELLIA_BLOCK_SIZE - 1];
        fprintf(stderr, "Last block: writing %d bytes \n", out_count);
        fwrite(out_buffer, 1, out_count, output);
    }


    if ((encrypt == CAMELLIA_ENCRYPT) && (n == 0)) {
        fprintf(stderr, "Last block: writing last padding block \n");
        memset(buffer, 0, CAMELLIA_BLOCK_SIZE);
        buffer[CAMELLIA_BLOCK_SIZE - 1] = CAMELLIA_BLOCK_SIZE;

        if (cbc == 1) {
            Camellia_cbc_encrypt(buffer, out_buffer, CAMELLIA_BLOCK_SIZE, &camellia_key, ivec, encrypt);
        } else {
            Camellia_ecb_encrypt(buffer, out_buffer, &camellia_key, encrypt);
        }

        fwrite(out_buffer, 1, CAMELLIA_BLOCK_SIZE, output);

    }

    fclose(input);
    fclose(output);
    return 0;
}