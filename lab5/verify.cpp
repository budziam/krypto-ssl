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

    /* Czastka hasha */
    MD5_CTX hashChunk;
    MD5_Init(&hashChunk);

    /* Obliczanie hasha */
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
    if (argc != 4) {
        fprintf(stderr, "Uzycie programu: verify\n nazwaPlikuKlucza nazwaPlikuDoWeryfikacji plikPodpisu\n");
        return 1;
    }


    char *keyFileName = argv[1];
    char *toVerifyFileName = argv[2];
    char *signFileName = argv[3];
    FILE *keyFile;
    FILE *signFile;
    RSA *rsaPublicKey;
    unsigned char *md5Vector;
    unsigned int signLength;
    /* do wczytywania klucza */
    long keySize;
    unsigned char *buffer;
    unsigned char *buffer2;

    /* wczytywanie klucza publicznego */
    rsaPublicKey = RSA_new();
    if ((keyFile = fopen(keyFileName, "rb")) == NULL) {
        fprintf(stderr, "cannot open keyFileName\n");
        return 1;
    }

    fseek(keyFile, 0, SEEK_END);
    keySize = ftell(keyFile);
    rewind(keyFile);

    buffer = (unsigned char *) malloc(keySize * sizeof(unsigned char));
    buffer2 = buffer; // jesli probuje bezposrednio to Naruszenie Ochrony Pamieci
    fread(buffer, sizeof(unsigned char), keySize, keyFile);
    d2i_RSAPublicKey(&rsaPublicKey, (const unsigned char **) &buffer2, keySize);
    fclose(keyFile);
    free(buffer);

    if (rsaPublicKey == NULL) {
        fprintf(stderr, "Cannot read rsaPublicKey\n");
        return 1;
    }

    md5Vector = md5sum(toVerifyFileName);

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

    if ((RSA_verify(NID_md5, md5Vector, sizeof(md5Vector), buffer, signLength, rsaPublicKey)) == 1) {
        printf("Sign is true\n");
    } else {
        printf("Sign is false\n");
    }

    free(md5Vector);
    free(buffer);
    RSA_free(rsaPublicKey);

    return 0;

}
