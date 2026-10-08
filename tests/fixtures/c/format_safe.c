#include <stdio.h>
#include <syslog.h>

void run(char *name, char *buf) {
    printf("hello %s", name);
    fprintf(stderr, "hello %s", name);
    snprintf(buf, 32, "hello %s", name);
    syslog(1, "hello %s", name);
}
