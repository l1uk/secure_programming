#include <assert.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/poll.h>
#include <unistd.h>

#include "hidden_functions/hidden_functions.h"

#define EXIT_FAILURE 1
#define EXIT_SUCCESS 0

int copy_file(const char * in, const char * out) {
    FILE * fds[2] = {NULL, NULL};

    fds[0] = fopen(in, "r");
    fds[1] = fopen(out, "w");

    // close files in case they're still open
    if(fds[0] == NULL || fds[1] == NULL){
        if (fds[0] != NULL) {
            fclose(fds[0]);
        }
        if (fds[1] != NULL) {
            fclose(fds[1]);
        }
        return EXIT_FAILURE;
    }

    int running = 1;

    const int buffer_size = 2048;

    while (running) {
        unsigned char buffer[buffer_size];
        const size_t  count = fread(buffer, sizeof(unsigned char), buffer_size, fds[0]);
        const size_t writn = fwrite(buffer, sizeof(unsigned char), count, fds[1]);

        running = !feof(fds[0]) && !ferror(fds[0]) && (writn == count);
    }

    fclose(fds[0]);
    fclose(fds[1]);

    return EXIT_SUCCESS;
}

int wait_confirmation(const char * in, const char * out) {
    printf("You are about to copy file %s in %s. Are you sure ? (y/N)\n", in,
           out);

    struct pollfd fds = {.fd = STDIN_FILENO, POLLIN, 0};

    const int test = poll(&fds, 1, (int) 1e3 * 3);
    if (test < 0) {
        perror("poll");
        return EXIT_FAILURE;
    } else if (test == 0) {
        fprintf(stderr, "Timeout.\n");
        return EXIT_FAILURE;
    }

    const unsigned char uc   = (unsigned char) getchar();
    const unsigned char valy = (uc ^ 'y') + (uc ^ 'Y');

    const int ok = (valy == 32);

    return (int) (ok != 1);
}
