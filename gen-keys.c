#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <openssl/rsa.h>
#include <openssl/engine.h>
#include <openssl/md5.h>
#include <openssl/bn.h>


int main(int argc, char* argv[]) {
    if (argc<3){
        fprintf(stderr, "Correct Syntax:\n genKeys privateKeyName publicKeyName keyLength\n");
        return 1;
    }
    char* privateKeyFileName = argv[1];
    char* publicKeyFileName = argv[2];
    char* keyLengthParameter = argv[3];

    RSA* key;
    FILE* out;
    FILE* keyInfo = fopen("INFO_O_KLUCZU","wb");

    int keyLength = atoi(keyLengthParameter); //Below 1024 should be considered insecure
    int exp = 3; // The exponent of e is an odd number, typically 3, 17 or 65537.
    int pkcsLength;
    unsigned char* buffer1;
    unsigned char* buffer2;
    key = RSA_generate_key(keyLength, exp, NULL, NULL);
    fprintf(keyInfo, "PUBLIC MODULUS: ");
    BN_print_fp(keyInfo, key->n);
    fprintf(keyInfo, "\nPUBLIC EXPONENT: ");
    BN_print_fp(keyInfo, key->e);
    fprintf(keyInfo, "\nPRIVATE EXPONENT: ");
    BN_print_fp(keyInfo, key->d);
    fprintf(keyInfo, "\nSCERET PRIME FACTOR P: ");
    BN_print_fp(keyInfo, key->d);
    fprintf(keyInfo, "\nSCERET PRIME FACTOR Q: ");
    BN_print_fp(keyInfo, key->q);
    fflush(keyInfo);
    fclose(keyInfo);
    if (RSA_check_key(key) != 1) {
        fprintf(stderr, "Please try again\n");
        return 1;
    }

    if ((out=fopen(publicKeyFileName,"wb"))==NULL){
        fprintf(stderr, "Can't open public key file\n");
        return 1;
    }

    pkcsLength = i2d_RSAPublicKey(key,NULL);
    buffer1=(unsigned char*)malloc(pkcsLength*sizeof(unsigned char));
    buffer2=buffer1;

    i2d_RSAPublicKey(key,&buffer2);

    fwrite(buffer1,sizeof(unsigned char),pkcsLength, out);
    fflush(out);
    fclose(out);
    free(buffer1);

    if ((out=fopen(privateKeyFileName, "wb"))==NULL){
        fprintf(stderr, "Can't open private key file\n");
        return 1;
    }
    pkcsLength=i2d_RSAPrivateKey(key,NULL);
    buffer1=(unsigned char*)malloc(pkcsLength*sizeof(unsigned char));
    buffer2=buffer1;
    i2d_RSAPrivateKey(key,&buffer2);

    fwrite(buffer1, sizeof(unsigned char), pkcsLength, out);
    fflush(out);
    fclose(out);
    free(buffer1);

    RSA_free(key);

    return 0;
}