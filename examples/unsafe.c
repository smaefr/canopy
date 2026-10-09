#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void handle(char *name, char *buf) {
    char password[] = "s3cr3t-value";
    strcpy(buf, name);
    printf(name);
    system(name);
}
