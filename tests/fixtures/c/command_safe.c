#include <stdio.h>
#include <stdlib.h>

void run(void) {
    system("ls");
    popen("ls", "r");
}
