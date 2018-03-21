#ifndef DIRENCRYPT_UTILS_H
#define DIRENCRYPT_UTILS_H

#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <errno.h>
#include <sys/stat.h>

void printerr(const char *module, const char *errmsg, const char *comment);
bool isdir(const char *path);
bool isreg(const char *path);
off_t fsize(const char *path);

extern char *module;

#endif //DIRENCRYPT_UTILS_H
