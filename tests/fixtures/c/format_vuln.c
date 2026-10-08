#include <stdio.h>
#include <syslog.h>

void run(char *name, char *buf) {
    printf(name);
    fprintf(stderr, name);
    sprintf(buf, name);
    snprintf(buf, 32, name);
    syslog(1, name);
}
