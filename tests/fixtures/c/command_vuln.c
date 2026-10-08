#include <stdio.h>
#include <stdlib.h>

void run(char *name) {
    system(name);
    popen(name, "r");
}
