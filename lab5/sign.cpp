#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <openssl/rsa.h>
#include <openssl/engine.h>
#include <openssl/md5.h>


unsigned char *md5sum(char *inputFileName) {
    FILE *inputFile;
    unsigned char inputVector[16];
    unsigned char *md5Vector = (unsigned char *) malloc(16 * sizeof(unsigned char));
    if ((inputFile = fopen(inputFileName, "rb")) == NULL) {
        fprintf(stderr, "Otwarcie pliku %s sie nie powiodlo\n", inputFileName);
        exit(1);
    }

    MD5_CTX hashChunk;
    MD5_Init(&hashChunk);

    size_t bytesRead;
    while (1) {
        bytesRead = fread(inputVector, sizeof(char), sizeof(inputVector), inputFile);
        if (bytesRead == 0) break;
        MD5_Update(&hashChunk, inputVector, bytesRead);
    }
    MD5_Final(md5Vector, &hashChunk);

    return md5Vector;
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
    unsigned char *md5Vector;

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

    md5Vector = md5sum(toSignFileName);

    buffer = (unsigned char *) malloc(RSA_size(rsaPrivateKey));//miejsce na podpis
    unsigned int signLength; //dlugosc podpisu
    if ((RSA_sign(NID_md5, md5Vector, sizeof(md5Vector), buffer, &signLength, rsaPrivateKey)) == 0) {
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
    free(md5Vector);
    free(signFileName);
    RSA_free(rsaPrivateKey);

    return 0;
}
