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
void readFile(char* fname, unsigned char* dest_string, int len){
    FILE *fp = fopen(fname, "r");
    if (fp) {
        fgets((char *)dest_string, len, fp);
        fclose(fp);
    } else {
        perror("Error opening file");
    }
}

unsigned char *computeSHA256(const unsigned char *data, size_t dataLen) {
    SHA256_CTX sha256;
    unsigned char *hash = malloc(dataLen);
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, data, dataLen);
    SHA256_Final(hash, &sha256);
    return hash;
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Error, missing argument\n");
        return 1;
    }

    const size_t  sz = strnlen(argv[1], MAX_INPUT_LENGTH);
    unsigned char in[MAX_INPUT_LENGTH];
	memset(in, 0, MAX_INPUT_LENGTH);
	memcpy(in, argv[1], sz);

    printf("You entered \"%s\".\n", in);
    unsigned char salt[MAX_INPUT_LENGTH];
    unsigned char hash[MAX_INPUT_LENGTH];
    unsigned char hash_hash[SHA256_DIGEST_LENGTH];

    readFile("salt.txt", salt, MAX_INPUT_LENGTH);
    readFile("hash.txt", hash, MAX_INPUT_LENGTH);
    printf("PASSWORD SALT:\n%s\n", salt);
    // Compute hash of the hash
    unsigned char *hash_ptr = computeSHA256(hash, strlen((char *)hash));
    memset(hash_hash, 0, SHA256_DIGEST_LENGTH);
    memcpy(hash_hash, hash_ptr, SHA256_DIGEST_LENGTH);

    free(hash_ptr);
    printf("HASH OF THE HASH:\n");
    long unsigned int i;
    for(i = 0; i < sizeof(hash_hash); i++) {
        printf("%0x", hash_hash[i]);
    }
    printf("\n");

    // Verify signature
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
    unsigned char RSA_output[RSA_size(rsa_public_key)];
    int result = RSA_public_decrypt(RSA_size(rsa_public_key), signature, RSA_output, rsa_public_key, RSA_NO_PADDING);
    if (result == -1) {
        ERR_print_errors_fp(stderr);
        printf("Signature verification failed.\n");
        return 1;
    }
    RSA_free(rsa_public_key);

    printf("Signature verified successfully.\n");
    // Clean up
    //RSA_free(rsa_public_key);
    printf("SALT:\n%s\n", salt);
    // Compute salted input hash
    char saltedInput[MAX_INPUT_LENGTH * 2];
    snprintf(saltedInput, sizeof(saltedInput), "%s%s", in, salt);

    printf("SALTED INPUT PASSWORD:\n%s\n", saltedInput);

    unsigned char *inputHash = computeSHA256((unsigned char *)saltedInput, strlen(saltedInput)-1);


    printf("ENTERED PASSWORD HASH:\n");
    for(i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        printf("%0x", inputHash[i]);
    }
    printf("\n");
    printf("READ PASSWORD HASH:\n%s\n", hash);

    // Compare hashes
    const unsigned char *pos = hash;
    unsigned char val[32];
    int return_value = 1;

    for (size_t count = 0; count < sizeof val/sizeof *val; count++) {
        sscanf((char *)pos, "%2hhx", &val[count]);
        pos += 2;
        return_value = return_value && (val[count] == inputHash[count]);
    }
    if(return_value == 1)
        printf("ACCESS GRANTED!");
    else
        printf("ACCESS DENIED");
    free(inputHash);

    printf("\n");
    return !return_value;
}
