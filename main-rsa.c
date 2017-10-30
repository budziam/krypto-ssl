#include<stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>


char prompt[]  = "[input] [output] [public/private key] -encrypt/decrypt";
const int padding = RSA_PKCS1_PADDING;
const int MAX_KEY_SIZE = 4096;
const int debug = 0;
int main(int argc, char* argv[]) {
    FILE *input, *output, *keyfile;
    int encrypt;
    RSA * key = RSA_new();
    unsigned char * keybuffer;
	if(argc < 5) {
		puts(prompt);
		return 1;
	}
	input = fopen(argv[1], "rb");
	output = fopen(argv[2], "wb");
	keyfile = fopen(argv[3], "rb");

	if((input == 0) || (output == 0) || (keyfile == 0)) {
	    if(input == 0)
	    puts("Error reading input file");
	    if(output == 0)
	    puts("Error reading output file");
	    if(keyfile == 0)
	    puts("Error reading key file");
		return 4;
	}

	if(!strcmp(argv[4], "-encrypt")) {
		encrypt = 1;
	} else if(!strcmp(argv[4], "-decrypt")) {
		encrypt = 0;
	} else {
		puts(prompt);
		return 3;
	}

    keybuffer = (unsigned char *) malloc(MAX_KEY_SIZE);
    int readBytes = fread(keybuffer, 1, MAX_KEY_SIZE, keyfile);
    if(debug) fprintf(stderr, "Read %d bytes\n", readBytes);

    if(encrypt == 1){
        d2i_RSAPublicKey(&key,  (const unsigned char**)&keybuffer, readBytes);
    }
    else {
        d2i_RSAPrivateKey(&key,  (const unsigned char**)&keybuffer, readBytes);
    }

    if(debug) fprintf(stderr, "RSA SIZE: %d\n", RSA_size(key));

    int block_size;
    if(encrypt == 1)
        block_size = RSA_size(key) - 12;
    else
        block_size = RSA_size(key);

    unsigned char * readBuffer, * writeBuffer;
    readBuffer = (unsigned char * ) malloc(RSA_size(key));
    writeBuffer = (unsigned char * ) malloc(RSA_size(key));

    int current_offset = 0;
    while(readBytes = fread(readBuffer, 1, block_size, input)) {
        if(debug) fprintf(stderr, "Read %d bytes\n", readBytes);
        if(debug) fprintf(stderr, "%s\n", readBuffer);
        int retSize;
        if(encrypt == 1) {
            retSize = RSA_public_encrypt(readBytes, readBuffer, writeBuffer, key, padding);
        } else {
            retSize = RSA_private_decrypt(readBytes, readBuffer, writeBuffer, key, padding);

        }
        if(retSize == -1) {
            if(debug) fprintf(stderr, "error");
        }
        fwrite(writeBuffer, 1, retSize, output);
        current_offset += readBytes;
    }


    return 0;
}