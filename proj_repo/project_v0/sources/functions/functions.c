#define _XOPEN_SOURCE 1
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "functions.h"
#include "hidden_functions/hidden_functions.h"

#define EXIT_FAILURE 1
#define EXIT_SUCCESS 0

int parse_options(int            argc,
                  char * const * argv,
                  char ** __restrict in,
                  char ** __restrict out) {
    for (int32_t i = 0; i < argc; i++) {
        const int option = getopt(argc, argv, "i:o:");
        switch (option) {
            case -1:
                /* No more options */
                i = INT32_MAX - 1;
                break;
            case (int) 'i':
                /* Input file */
                *in = (char *) malloc(sizeof(char) * strlen(optarg) + 1); // +1 for the null terminator
                // check if malloc() worked correctly
                if (in == NULL) {
                    fprintf(stderr, "Error: Memory allocation failed.\n");
                    exit(EXIT_FAILURE);
                }
                // Substituted strcpy with strncpy
                strncpy(*in, optarg, strlen(optarg) + 1);
                break;
            case (int) 'o':
                /* Output file */
                *out = (char *) malloc(sizeof(char) * strlen(optarg) + 1); // +1 for the null terminator
                // check if malloc() worked correctly
                if (out == NULL) {
                    fprintf(stderr, "Error: Memory allocation failed.\n");
                    exit(EXIT_FAILURE);
                }
                // Substituted strcpy with strncpy
                strncpy(*in, optarg, strlen(optarg) + 1);
                break;
            case (int) '?':
                /* Ambiguous or unknown */
                (void) fprintf(stderr, "Unknown or ambiguous value.\n");
                return EXIT_FAILURE;

            default:
                /* Unexpected error */
                (void) fprintf(stderr, "An unexpected error occured.\n");
                return EXIT_FAILURE;
        }
    }

    return EXIT_SUCCESS;
}

int secure_copy_file(const char * in, const char * out) {
    int error = 0;
    // moved prompt before performing acess check
    // this is to avoid an attack where the file is changed
    // it is copied, but after the check is performed.
    error = wait_confirmation(in, out);
    if (!error) {
        error = access(out, W_OK);
        if (!error) {
            error = access(in, R_OK);
            if(!error)
                copy_file(in, out);
            else
                fprintf(stderr, "File %s cannot be read.\n", in);
        } else {
            fprintf(stderr, "File %s cannot be written.\n", out);
        }
    } else {
        fprintf(stderr, "Error during prompt.\n");
    }

    return error;
}
