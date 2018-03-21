#include "utils.h"

void printerr(const char *module, const char *errmsg, const char *comment)
{
    fprintf(stderr, "%s: %s (%s)\n", module, errmsg, comment ? comment : "");
}

bool isdir(const char *path)
{
    struct stat statbuf;

    if (lstat(path, &statbuf) == -1) {
        printerr(module, strerror(errno), path);
        return false;
    }

    return S_ISDIR(statbuf.st_mode);
}

bool isreg(const char *path)
{
    struct stat statbuf;

    if (lstat(path, &statbuf) == -1) {
        printerr(module, strerror(errno), path);
        return false;
    }

    return S_ISREG(statbuf.st_mode);
}

off_t fsize(const char *path)
{
    struct stat statbuf;

    if (lstat(path, &statbuf) == -1) {
        printerr(module, strerror(errno), path);
        return -1;
    }

    return statbuf.st_size;
}