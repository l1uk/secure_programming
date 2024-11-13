#include <stdio.h>
#include <string.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#define MAX_INPUT_LENGTH 100
RSA *load_public_key(const char *public_key_file) {
    FILE *fp = fopen(public_key_file, "r");
    if (!fp) {
        perror("Error opening public key file");
        return NULL;
    }

    RSA *rsa = PEM_read_RSA_PUBKEY(fp, NULL, NULL, NULL);
    fclose(fp);

    if (!rsa) {
        ERR_print_errors_fp(stderr);
        return NULL;
    }

    return rsa;
}
void readFile(char* fname, unsigned char* dest_string){
    FILE *fptr;
        // Open a file in read mode
    fptr = fopen(fname, "r");

    // If the file exist
    if(fptr != NULL) {

    // Read the content and print it
    while(fgets((char *)dest_string, MAX_INPUT_LENGTH, fptr)) {}

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
    unsigned char salt_file[MAX_INPUT_LENGTH];
    unsigned char hash_file[MAX_INPUT_LENGTH];
    int return_value = 1;
    memset(salt_file, 0, MAX_INPUT_LENGTH);
    memset(hash_file, 0, MAX_INPUT_LENGTH);
    memset(buffer, 0, SHA256_DIGEST_LENGTH);
	memset(in, 0, MAX_INPUT_LENGTH);
	memcpy(in, argv[1], sz);
    printf("You entered \"%s\".\n", argv[1]);

    readFile("salt.txt", salt_file);

    readFile("hash.txt", hash_file);
    printf("PASSWORD SALT:\n%s\n", salt_file);
    printf("Computing hash of the hash\n");

    FILE *fp = fopen("hash.txt", "rb");
    if (!fp) {
        perror("Error opening file");
        return 1;
    }
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    unsigned char buf[1024];
    size_t len;
    while ((len = fread(buf, 1, 1024, fp)) > 0) {
        SHA256_Update(&sha256, buf, len);
    }
    fclose(fp);

    unsigned char hash_hash[MAX_INPUT_LENGTH];
    SHA256_Final(hash_hash, &sha256);
    printf("HASH OF THE HASH:\n");
    long unsigned int i;
    for(i = 0; i < sizeof(hash_hash); i++) {
        printf("%0x", hash_hash[i]);
    }
    printf("\n");

    printf("Verifying signature\n");

    RSA *rsa_public_key = load_public_key("public_key.pem");
    if (!rsa_public_key) {
        ERR_print_errors_fp(stderr);
        return 1;
    }

    // Read the signature from the file
    FILE *sig_file = fopen("signature.bin", "rb");
    if (!sig_file) {
        perror("Error opening signature file");
        return 1;
    }

    unsigned char signature[RSA_size(rsa_public_key)];
    long unsigned int sig_len = fread(signature, 1, RSA_size(rsa_public_key), sig_file);
    if (sig_len <= 0) {
        perror("Error reading signature from file");
        fclose(sig_file);
        return 1;
    }
    fclose(sig_file);

    printf("SIGNATURE READ FROM FILE:\n");
    for(i = 0; i < sizeof(signature); i++) {
        printf("%0x", signature[i]);
    }
    printf("\n");

    int result = RSA_public_decrypt(RSA_size(rsa_public_key), signature, hash_hash, rsa_public_key, RSA_NO_PADDING);
    if (result == -1) {
        ERR_print_errors_fp(stderr);
        printf("Signature verification failed.\n");
        return 1;
    }

    printf("Signature verified successfully.\n");

    // Clean up
    RSA_free(rsa_public_key);

    printf("PASSWORD HASH:\n%s\n", hash_file);
    printf("SALT:\n %s\n", salt_file);
    const size_t  sz_salt = strnlen((char *)salt_file, MAX_INPUT_LENGTH);

    //concat input string and hash
    char salted_input[MAX_INPUT_LENGTH*2];
    snprintf(salted_input, sizeof(salted_input), "%s%s", in, salt_file);
    printf("SALTED INPUT PASSWORD:\n%s\n", salted_input);

	(void) SHA256((unsigned char *) salted_input, sz + sz_salt-1, buffer);

    // converting hash to string

    const unsigned char *pos = hash_file;
    unsigned char val[32];

    for (size_t count = 0; count < sizeof val/sizeof *val; count++) {
        sscanf((char *)pos, "%2hhx", &val[count]);
        pos += 2;
        return_value = return_value && (val[count] == buffer[count]);
    }
    printf("ENTERED PASSWORD HASH:\n");
    //int i;
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
