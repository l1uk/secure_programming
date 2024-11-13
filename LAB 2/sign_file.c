#include <stdio.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define MAX_INPUT_LENGTH 100
// Function to generate a new RSA key pair
int generate_keypair(const char *public_key_file, const char *private_key_file) {
    if (access(public_key_file, F_OK) == 0 && access(private_key_file, F_OK) == 0) {
        printf("Key files already exist. Skipping key generation.\n");
        return 0; // Exit without generating keys
    }

    // Generate the key pair
    RSA *rsa = RSA_generate_key(2048, RSA_F4, NULL, NULL);
    if (!rsa) {
        ERR_print_errors_fp(stderr);
        return 1;
    }

    // Write the public key to a file
    FILE *pub_file = fopen(public_key_file, "w");
    if (!pub_file) {
        perror("Error opening public key file");
        RSA_free(rsa);
        return 1;
    }
    PEM_write_RSA_PUBKEY(pub_file, rsa);
    fclose(pub_file);

    // Write the private key to a file
    FILE *priv_file = fopen(private_key_file, "w");
    if (!priv_file) {
        perror("Error opening private key file");
        RSA_free(rsa);
        return 1;
    }
    PEM_write_RSAPrivateKey(priv_file, rsa, NULL, NULL, 0, NULL, NULL);
    fclose(priv_file);

    RSA_free(rsa);
    return 0;
}

// Function to load a private key from a file
RSA *load_private_key(const char *private_key_file) {
    FILE *fp = fopen(private_key_file, "r");
    if (!fp) {
        perror("Error opening private key file");
        return NULL;
    }

    RSA *rsa = PEM_read_RSAPrivateKey(fp, NULL, NULL, NULL);
    fclose(fp);

    if (!rsa) {
        ERR_print_errors_fp(stderr);
        return NULL;
    }

    return rsa;
}

// Function to load a public key from a file
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

int main(int argc, char * argv[]) {
	if (argc < 2){
		printf("Error, missing argument\n");
		return 1;
	}
	const size_t  sz = strnlen(argv[1], MAX_INPUT_LENGTH);
    unsigned char in[MAX_INPUT_LENGTH];
    memset(in, 0, MAX_INPUT_LENGTH);
	memcpy(in, argv[1], sz);

    printf("Generating key pair\n");
    generate_keypair("public_key.pem", "private_key.pem");

    printf("Loading private key\n");
    RSA *rsa_private_key = load_private_key("private_key.pem");

    printf("Signing file \"%s\".\n", in);

    FILE *fp = fopen(in, "rb");
    if (!fp) {
        perror("Error opening file");
        return 1;
    }
    printf("Computing hash\n");
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    unsigned char buffer[1024];
    size_t len;
    while ((len = fread(buffer, 1, 1024, fp)) > 0) {
        SHA256_Update(&sha256, buffer, len);
    }
    fclose(fp);
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_Final(hash, &sha256);
    printf("Signing hash\n");
    // Sign the hash
    unsigned char signature[RSA_size(rsa_private_key)];
    int sig_len = RSA_private_encrypt(RSA_size(rsa_private_key), hash, signature, rsa_private_key, RSA_NO_PADDING);
    if (sig_len <= 0) {
        ERR_print_errors_fp(stderr);
        return 1;
    }

    FILE *sig_file = fopen("signature.bin", "wb");
    if (!sig_file) {
        perror("Error opening signature file");
        return 1;
    }

    if (fwrite(signature, 1, sig_len, sig_file) != sig_len) {
        perror("Error writing signature to file");
        fclose(sig_file);
        return 1;
    }

    fclose(sig_file);
}
