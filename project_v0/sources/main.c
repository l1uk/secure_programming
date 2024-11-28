#include "functions/functions.h"
#include <stdio.h>
#include <stdlib.h>

#define EXIT_FAILURE 1
#define EXIT_SUCCESS 0
int main(int argc, char * argv[]) {

    char * input  = NULL;
    char * output = NULL;

    /* Parse user inputs and check conformance */
    const int error = parse_options(argc, argv, &input, &output);
    if (error) {
        if (input != NULL) {
            free(input);
        }
        if (output != NULL) {
            free(output);
        }
        return EXIT_FAILURE;
    }

    if (input == NULL || output == NULL) {
        fprintf(stderr, "'-o <out>' and '-i <in>' have to be provided.\n");
        // de allocate not null pointer
        if (input != NULL) {
            free(input);
        }
        if (output != NULL) {
            free(output);
        }
        return EXIT_FAILURE;
    }


    /* Securely copy input file to output file */
    const int result = secure_copy_file(input, output);

    if (input != NULL) {
        free(input);
    }
    if (output != NULL) {
        free(output);
    }

    return result;
}
