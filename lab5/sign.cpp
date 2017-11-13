#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <openssl/rsa.h>
#include <openssl/engine.h>
#include <openssl/sha.h>


unsigned char *sha512_sum(char *inputFileName) {
    FILE *inputFile;
    unsigned char inputVector[512];
    unsigned char *sha512_vector = (unsigned char *) malloc(512 * sizeof(unsigned char));
    if ((inputFile = fopen(inputFileName, "rb")) == NULL) {
        fprintf(stderr, "Otwarcie pliku %s sie nie powiodlo\n", inputFileName);
        exit(1);
    }

    SHA512_CTX hashChunk;
    SHA512_Init(&hashChunk);

    size_t bytesRead;
    while (1) {
        bytesRead = fread(inputVector, sizeof(char), sizeof(inputVector), inputFile);
        if (bytesRead == 0) break;
        SHA512_Update(&hashChunk, inputVector, bytesRead);
    }
    SHA512_Final(sha512_vector, &hashChunk);

    return sha512_vector;
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        fprintf(stderr, "Usage:\n fileToSign privateKeyPath\n");
        return 1;
    }

    char *keyFileName = argv[2];
    char *toSignFileName = argv[1];
    char *signFileName;
    FILE *keyFile;
    FILE *signFile;
    RSA *rsaPrivateKey;
    unsigned char *sha512_vector;

    long keySize;
    unsigned char *buffer;
    unsigned char *buffer2;

    signFileName = (char *) malloc(sizeof(toSignFileName) + 4 * sizeof(char));
    strcpy(signFileName, toSignFileName);
    strcat(signFileName, ".sig");

    rsaPrivateKey = RSA_new();
    if ((keyFile = fopen(keyFileName, "rb")) == NULL) {
        fprintf(stderr, "Open rb priv key error\n");
        return 1;
    }

    fseek(keyFile, 0, SEEK_END);
    keySize = ftell(keyFile);
    rewind(keyFile);

    buffer = (unsigned char *) malloc(keySize * sizeof(unsigned char));
    buffer2 = buffer;
    fread(buffer, sizeof(unsigned char), keySize, keyFile);
    d2i_RSAPrivateKey(&rsaPrivateKey, (const unsigned char **) &buffer2, keySize);
    fclose(keyFile);
    free(buffer);

    if (rsaPrivateKey == NULL) {
        fprintf(stderr, "Read priv key error\n");
        return 1;
    }

    sha512_vector = sha512_sum(toSignFileName);

    buffer = (unsigned char *) malloc(RSA_size(rsaPrivateKey));
    unsigned int signLength;
    if ((RSA_sign(NID_sha512, sha512_vector, sizeof(sha512_vector), buffer, &signLength, rsaPrivateKey)) == 0) {
        fprintf(stderr, "Problem with signing a file\n");
        return 1;
    }

    if ((signFile = fopen(signFileName, "wb")) == NULL) {
        fprintf(stderr, "Open file to save sign error\n");
        return 1;
    }
    fwrite(buffer, sizeof(unsigned char), signLength, signFile);

    fflush(signFile);
    fclose(signFile);

    free(buffer);
    free(sha512_vector);
    free(signFileName);
    RSA_free(rsaPrivateKey);

    return 0;
}
