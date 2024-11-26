#include <stdio.h>
#include <string.h>

#include "validation_functions.h"

int fnchck(int a, int b) {
    int check;

    if (b == a) {
        puts("Valid access.");
        check = 0xf;
    } else {
        check = 0;
    }
    return check;
}

int validate(char * argv[]) {
    char buffer[20];
    printf("You entered %s and %s. \nDo you agree ? (Y,n):\n", argv[1], argv[2]);
    scanf("%s", buffer);
    return strcmp(buffer, "Y") && strcmp(buffer, "y");
}
