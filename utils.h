#ifndef DIRENCRYPT_UTILS_H
#define DIRENCRYPT_UTILS_H

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <errno.h>
#include <unistd.h>
#include <syscall.h>
#include <dirent.h>
#include <sys/stat.h>

void printerr(const char *module, const char *errmsg, const char *comment);
bool isdir(const char *path);
bool isemptydir(const char *path);
bool isreg(const char *path);
off_t fsize(const char *path);
void create_filepath(char *dest, const char *path, const char *name);
void report_thread_status(const char *filepath, size_t ciphered_bytes);

extern char *module;

#endif //DIRENCRYPT_UTILS_H
