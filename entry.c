#include "ecc.h"
#include "sha256.h"
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>

#define FILE_MAX 327680

void encode(unsigned char *output,unsigned int *input,unsigned int len)
{
    unsigned int i = 0,j = 0;
    while(j < len)
    {
         output[j] = input[i] & 0xFF;  
         output[j+1] = (input[i] >> 8) & 0xFF;
         output[j+2] = (input[i] >> 16) & 0xFF;
         output[j+3] = (input[i] >> 24) & 0xFF;
         i++;
         j+=4;
    }
}

int main()
{
	uint8_t public_key[ECC_BYTES + 1];
	uint8_t private_key[ECC_BYTES];
	uint8_t hash[ECC_BYTES];
	uint8_t signature[ECC_BYTES * 2];
    uint32_t i = 0;
    int ret = 0;

	int fd;
	fd = open("./update.zip",O_RDONLY);
	if(fd<0){
		perror("file open");
	}

	char filebuf[FILE_MAX];
	int filesz=read(fd,filebuf,FILE_MAX);
	if(filesz<0){
		perror("file read");
	}

	sha256(filebuf,filesz,hash);

	printf("sha256:\n");
	for (i = 0; i < SHA256_BYTES; i++)
		printf("%02x%s", hash[i], ((i % 4) == 3) ? " " : "");
	putchar('\n\n');

    ret = ecc_make_key(public_key, private_key);
    if (ret == 0) {
        printf("ecc_make_key failure\n");
    }

    printf("##############public key###############\n");
    for (i = 0;i < ECC_BYTES + 1;i++) {
        printf("%x ", public_key[i]);
    }

    printf("\n\n");
    printf("##############private key###############\n");
    for (i = 0;i < ECC_BYTES;i++) {
        printf("%x ", private_key[i]);
    }
    printf("\n\n");

    ret = ecdsa_sign(private_key, hash, signature);
    if (ret == 0) {
        printf("ecdsa_sign failure\n");
    }

    ret = ecdsa_verify(public_key, hash, signature);
    if (ret == 1) {
        printf("verify passed\n");
    } else {
        printf("verify failed\n");
    }

    return 0;
}
