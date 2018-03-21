#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include "utils.h"

#define MIN_VALID_ARGC 4
#define MIN_RUNNING_THREADS 2
#define CHAR_BUF_SIZE 256

struct mapstruct
{
    char *addr;
    size_t filesize;
};

char *module;

int create_key_map(const char *keyfile, struct mapstruct *map);
int destroy_key_map(struct mapstruct *map);
int encrypt_files(const char *dirpath, int depth, long max_running_threads);

int main(int argc, char *argv[]) {
    module = basename(argv[0]);

    if (argc < MIN_VALID_ARGC) {
        printerr(module, "Too few arguments", NULL);
        return 1;
    }
    if (!isdir(argv[1])) {
        printerr(module, "Not a directory", argv[1]);
        return 1;
    }
    if (!isreg(argv[2])) {
        printerr(module, "Not a regular file", argv[2]);
        return 1;
    }

    long max_running_threads;
    if (!(max_running_threads = strtol(argv[3], NULL, 10))) {
        printerr(module, "Maximum of running threads is not an integer", NULL);
        return 1;
    }
    if (errno == ERANGE) {
        printerr(module, strerror(errno), NULL);
        return 1;
    }
    if (max_running_threads < MIN_RUNNING_THREADS) {
        char errmsg[CHAR_BUF_SIZE];
        sprintf(errmsg, "Maximum of running threads must be greater or equal to %d",
                MIN_RUNNING_THREADS);

        printerr(module, errmsg, NULL);
        return 1;
    }

    struct mapstruct key_map;
    if (create_key_map(argv[2], &key_map) == -1) {
        return 1;
    }

    int result = encrypt_files(argv[1], 1, max_running_threads);

    destroy_key_map(&key_map);

    return result;
}

int create_key_map(const char *keyfile, struct mapstruct *map)
{
    int fd;
    if (fd = open(keyfile, O_RDONLY), fd == -1) {
        printerr(module, strerror(errno), keyfile);
        return -1;
    }

    off_t filesize;
    if (filesize = fsize(keyfile), filesize == -1) {
        return -1;
    }
    char *memblock = mmap(NULL, (size_t) filesize, PROT_READ, MAP_PRIVATE, fd, 0);

    if (close(fd) == -1) {
        printerr(module, strerror(errno), keyfile);
        return -1;
    }

    map->addr = memblock;
    map->filesize = (size_t) filesize;

    return 0;
}

int destroy_key_map(struct mapstruct *map)
{
    if (munmap(map->addr, map->filesize) == -1) {
        printerr(module, strerror(errno), "munmap");
    }
    return 0;
}

int encrypt_files(const char *dirpath, int depth, long max_running_threads)
{
    return 0;
}