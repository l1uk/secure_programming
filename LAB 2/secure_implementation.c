#include <openssl/sha.h>
#include <stdio.h>
#include <string.h>



extern unsigned char passwd_hash[SHA256_DIGEST_LENGTH];

void readFile(char* fname, char* dest_string){
    FILE *fptr;
        // Open a file in read mode
    fptr = fopen(fname, "r");

    // If the file exist
    if(fptr != NULL) {

    // Read the content and print it
    while(fgets(dest_string, 100, fptr)) {
        1;
    }

    // If the file does not exist
    } else {
        printf("Not able to open the file.");
    }

    // Close the file
    fclose(fptr);
}

int main(int argc, char * argv[]) {
	if (argc < 2){
		printf("Error, missing argument");
		return 1;
	}

	unsigned char buffer[SHA256_DIGEST_LENGTH];

	const size_t  sz = strnlen(argv[1], 40);
	unsigned char in[40];
    unsigned char salt[100];
    unsigned char hash[100];
    int return_value = 1;
    memset(salt, 0, 100);
    memset(hash, 0, 100);
	memset(in, 0, 40);
	memcpy(in, argv[1], sz);
    printf("You entered \"%s\".\n", argv[1]);

    readFile("salt.txt", salt);
    readFile("hash.txt", hash);

    printf("PASSWORD HASH:\n%s\n", hash);
    printf("SALT: %s\n", salt);
    const size_t  sz_salt = strnlen(salt, 100);

    //concat input string and hash
    char salted_input[80];
    snprintf(salted_input, sizeof(salted_input), "%s%s", in, salt);
    printf("SALTED INPUT PASSWORD:\n%s\n", salted_input);

	(void) SHA256((unsigned char *) salted_input, sz + sz_salt-1, buffer);

    // converting hash to string

    const char *pos = hash;
    unsigned char val[32];

    for (size_t count = 0; count < sizeof val/sizeof *val; count++) {
        sscanf(pos, "%2hhx", &val[count]);
        pos += 2;
        return_value = return_value && (val[count] == buffer[count]);
    }
    printf("ENTERED PASSWORD HASH:\n");
    int i;
    for(i = 0; i < sizeof(buffer); i++) {
        printf("%0x", buffer[i]);
    }
    printf("\n");

    if(return_value == 1)
        printf("ACCESS GRANTED!");
    else
        printf("ACCESS DENIED");

    printf("\n");

	return return_value;
}
