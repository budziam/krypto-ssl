#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <openssl/rsa.h>
#include <openssl/engine.h>
#include <openssl/md5.h>

int main(int argc, char* argv[]){
	if (argc<2){
		fprintf(stderr, "Uzycie programu:generateKeys\n nazwaKluczaPrywatnego nazwaPlikuKluczaPublicznego\n");
		return 1;
	}
	char* privateFileName = argv[1];
	char* publicFileName = argv[2];	
	RSA* newRsaKey;
	FILE* outputFile;
	int dlugoscKlucza=1024; //ustalamy d³ugoœæ klucza
	int exp=3; //zazwyczaj jakas nieparzysta liczba zwykle 3 lub 65535

	/* potrzebne do kodowania klucza do PKCS */
	int length; //dlugosc zapisywanego klucza w PKCS
	unsigned char* buffer; //buffor na klucz w PKCS
	unsigned char* buffer2; //buffor pomocniczy

	
	/* generowanie klucza RSA */
	newRsaKey=RSA_generate_key(dlugoscKlucza,exp,NULL, NULL); //generowanie klucza RSA_generate_key(dlugosc klucza {512,1024,2048,...}, exp (nieparzysta liczba), callback function (niepotrzebna=NULL), argumenty callback function? (niepotrzebne=NULL)
	if (RSA_check_key(newRsaKey)!=1){ // sprawdzanie poprawnosci wygenerowanego klucza
		fprintf(stderr, "Promienieowanie kosmiczne i pogda za oknem s¹ winne temu b³êdowi\n");
		return 1;
	} 
	
	/* zapis klucza publicznego */
	if ((outputFile=fopen(publicFileName,"wb"))==NULL){
		fprintf(stderr, "Nie udalo sie otworzyc pliku do zapisu klucza publicznego\n");
		return 1;
	}
	
	length=i2d_RSAPublicKey(newRsaKey,NULL); //ustalam wielkosc buffora i2d_RSAPublicKey(*KluczRSA,**BufforUnsignedCharDoZapisu) 
	buffer=(unsigned char*)malloc(length*sizeof(unsigned char));
	buffer2=buffer; //jesli probuje uzywac ponizszej funkcji bezposrednio na buffer to wywala naruszenie ochrony pamieci
	i2d_RSAPublicKey(newRsaKey,&buffer2); //kodowanie publicznego do PKCS
	
	fwrite(buffer,sizeof(unsigned char),length,outputFile);
	fflush(outputFile);
	fclose(outputFile);
	free(buffer);
	
	/* zapis klucza prywatnego */
	if ((outputFile=fopen(privateFileName, "wb"))==NULL){
		fprintf(stderr, "Coœ siê posypa³o z zapisem... sorry\n");
		return 1;
	}
	/* analogicznie do publicznego */
	length=i2d_RSAPrivateKey(newRsaKey,NULL);
	buffer=(unsigned char*)malloc(length*sizeof(unsigned char));
	buffer2=buffer;
	i2d_RSAPrivateKey(newRsaKey,&buffer2);
	
	fwrite(buffer,sizeof(unsigned char),length,outputFile);
	fflush(outputFile);
	fclose(outputFile);
	free(buffer);
	
	RSA_free(newRsaKey);
	
	
    return 0; 
}
