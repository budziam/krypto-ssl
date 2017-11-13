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
    if (argc != 4) {
        fprintf(stderr, "Usage: verify\n publicKeyPath toVerifyFileName signFile\n");
        return 1;
    }

    char *keyFileName = argv[1];
    char *toVerifyFileName = argv[2];
    char *signFileName = argv[3];
    FILE *keyFile;
    FILE *signFile;
    RSA *rsaPublicKey;
    unsigned char *sha512_vector;
    unsigned int signLength;

    long keySize;
    unsigned char *buffer;
    unsigned char *buffer2;

    rsaPublicKey = RSA_new();
    if ((keyFile = fopen(keyFileName, "rb")) == NULL) {
        fprintf(stderr, "cannot open keyFileName\n");
        return 1;
    }

    fseek(keyFile, 0, SEEK_END);
    keySize = ftell(keyFile);
    rewind(keyFile);

    buffer = (unsigned char *) malloc(keySize * sizeof(unsigned char));
    buffer2 = buffer;
    fread(buffer, sizeof(unsigned char), keySize, keyFile);
    d2i_RSAPublicKey(&rsaPublicKey, (const unsigned char **) &buffer2, keySize);
    fclose(keyFile);
    free(buffer);

    if (rsaPublicKey == NULL) {
        fprintf(stderr, "Cannot read rsaPublicKey\n");
        return 1;
    }

    sha512_vector = sha512_sum(toVerifyFileName);

    if ((signFile = fopen(signFileName, "rb")) == NULL) {
        fprintf(stderr, "Cannot open file signFileName\n");
        return 1;
    }

    fseek(signFile, 0, SEEK_END);
    signLength = ftell(signFile);
    rewind(signFile);

    buffer = (unsigned char *) malloc(signLength * sizeof(unsigned char));
    fread(buffer, sizeof(unsigned char), signLength, signFile);
    fclose(signFile);

    if ((RSA_verify(NID_sha512, sha512_vector, sizeof(sha512_vector), buffer, signLength, rsaPublicKey)) == 1) {
        printf("Sign is true\n");
    } else {
        printf("Sign is false\n");
    }

    free(sha512_vector);
    free(buffer);
    RSA_free(rsaPublicKey);

    return 0;

}
