#include <openssl/sha.h>
#include <stdio.h>
#include <string.h>

#define MAX_INPUT_LENGTH 100

extern unsigned char passwd_hash[SHA256_DIGEST_LENGTH];

//TODO: file signature verification https://pagefault.blog/2019/04/22/how-to-sign-and-verify-using-openssl/

void readFile(char* fname, char* dest_string){
    FILE *fptr;
        // Open a file in read mode
    fptr = fopen(fname, "r");

    // If the file exist
    if(fptr != NULL) {

    // Read the content and print it
    while(fgets(dest_string, MAX_INPUT_LENGTH, fptr)) {
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

	const size_t  sz = strnlen(argv[1], MAX_INPUT_LENGTH);
	unsigned char in[MAX_INPUT_LENGTH];
    unsigned char salt[MAX_INPUT_LENGTH];
    unsigned char hash[MAX_INPUT_LENGTH];
    int return_value = 1;
    memset(salt, 0, MAX_INPUT_LENGTH);
    memset(hash, 0, MAX_INPUT_LENGTH);
	memset(in, 0, MAX_INPUT_LENGTH);
	memcpy(in, argv[1], sz);
    printf("You entered \"%s\".\n", argv[1]);

    readFile("salt.txt", salt);
    readFile("hash.txt", hash);

    printf("PASSWORD HASH:\n%s\n", hash);
    printf("SALT: %s\n", salt);
    const size_t  sz_salt = strnlen(salt, MAX_INPUT_LENGTH);

    //concat input string and hash
    char salted_input[MAX_INPUT_LENGTH*2];
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
