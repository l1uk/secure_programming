#include "action_functions.h"

#include <stdio.h>
#include <stdlib.h>

void fnr(void) {
    puts("The door is locked.");
    return;
}

void fngrt(void) {
    puts("Opened.");
    puts("No root.");
    return;
}

void fnR(void) {
    puts("Opened.");
    puts("Be careful, you are ROOT !\n");
    int value = system("/usr/bin/env PS1=\"SUPPOSED ROOT SHELL > \" python3 -c 'import pty; pty.spawn([\"/bin/bash\", \"--norc\"])'");
    exit(value);
}

