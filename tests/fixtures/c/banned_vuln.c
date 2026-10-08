void run(char *name, char *buf) {
    gets(buf);
    strcpy(buf, name);
    strcat(buf, name);
    sprintf(buf, "%s", name);
    vsprintf(buf, name, 0);
    mktemp(buf);
    tmpnam(buf);
    scanf("%s", buf);
}
