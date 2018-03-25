#include "utils.h"

void printerr(const char *module, const char *errmsg, const char *comment)
{
    fprintf(stderr, "%s: %s ", module, errmsg);
    if (comment) {
        fprintf(stderr, "(%s)", comment);
    }
    fprintf(stderr, "\n");
}

bool isdir(const char *path)
{
    struct stat statbuf;

    if (lstat(path, &statbuf) == -1) {
        return false;
    }

    return S_ISDIR(statbuf.st_mode);
}

bool isemptydir(const char *path)
{
    DIR *currdir;
    if (!(currdir = opendir(path))) {
        printerr(module, strerror(errno), path);
        return false;
    }

    struct dirent *entry = readdir(currdir);
    while (entry && (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, ".."))) {
        entry = readdir(currdir);
    }

    bool result = readdir(currdir) == NULL;
    closedir(currdir);

    return result;
}

bool isreg(const char *path)
{
    struct stat statbuf;

    if (lstat(path, &statbuf) == -1) {
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

void create_filepath(char *dest, const char *path, const char *name)
{
    strcpy(dest, path);
    strcat(dest, "/");
    strcat(dest, name);
}

void report_thread_status(const char *filepath, size_t ciphered_bytes)
{
    printf("I am %ld, have processed %s and encrypted %zu bytes\n", syscall(SYS_gettid), filepath, ciphered_bytes);
}