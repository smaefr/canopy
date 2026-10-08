#include <stdio.h>
#include <string.h>

void run(char *name, char *buf, size_t n) {
    fgets(buf, (int)n, stdin);
    strncpy(buf, name, n - 1);
    strncat(buf, name, n - 1);
    snprintf(buf, n, "%s", name);
    scanf("%10s", buf);
}
