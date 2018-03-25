#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdint.h>
#include <fcntl.h>
#include <dirent.h>
#include <unistd.h>
#include <sys/mman.h>
#include <pthread.h>
#include "utils.h"
#include "pthread_routines.h"

#define MIN_VALID_ARGC 5
#define MIN_RUNNING_THREADS 1
#define CHAR_BUF_SIZE 256
#define BLOCK_SIZE 512

struct mapconf_t
{
    char *addr;
    size_t filesize;
};

struct encrypter_params_t
{
    char plaintext_filepath[PATH_MAX];
    char ciphertext_filepath[PATH_MAX];
    struct mapconf_t *map;
    enum tstatus_t *thread_status;
};

char *module;
struct tconf_t *threads;

int create_key_map(const char *key_filename, struct mapconf_t *map);
int destroy_key_map(struct mapconf_t *map);
int encrypt_files(const char *dirpath, int depth, const char *ciphertext_dirpath,
    struct mapconf_t *key_map, long max_running_threads);
void *encryption_worker(void *args);
uint8_t get_key_byte(struct mapconf_t *map, long long *pos);

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
    if (!isreg(argv[3])) {
        printerr(module, "Not a regular file", argv[3]);
        return 1;
    }

    long max_running_threads;
    if (!(max_running_threads = strtol(argv[4], NULL, 10))) {
        printerr(module, "Maximum of running encrypting threads is not an integer", NULL);
        return 1;
    }
    if (errno == ERANGE) {
        printerr(module, strerror(errno), NULL);
        return 1;
    }
    if (max_running_threads < MIN_RUNNING_THREADS) {
        char errmsg[CHAR_BUF_SIZE];
        sprintf(errmsg, "Maximum of running encrypting threads must be greater or equal to %d",
            MIN_RUNNING_THREADS);

        printerr(module, errmsg, NULL);
        return 1;
    }

    if (!isdir(argv[2])) {
        if (mkdir(argv[2], 0777) == -1) {
            printerr(module, strerror(errno), argv[2]);
            return 1;
        }
    } else if (!isemptydir(argv[2])) {
        printerr(module, "Is not an empty directory", argv[2]);
        return 1;
    }

    threads = malloc(max_running_threads * sizeof(struct tconf_t));
    for (long i = 0; i < max_running_threads; i++) {
        threads[i].thread_status = ST_NULL;
    }

    struct mapconf_t key_map;
    if (create_key_map(argv[3], &key_map) == -1) {
        return 1;
    }

    int result = encrypt_files(argv[1], 1, argv[2], &key_map, max_running_threads);
    while (!are_finished_threads(threads, max_running_threads)) {
        /* block */
    }

    destroy_key_map(&key_map);

    return result;
}

int create_key_map(const char *key_filename, struct mapconf_t *map)
{
    int fd;
    if (fd = open(key_filename, O_RDONLY), fd == -1) {
        printerr(module, strerror(errno), key_filename);
        return -1;
    }

    off_t filesize;
    if (filesize = fsize(key_filename), filesize == -1) {
        return -1;
    }
    char *memblock = mmap(NULL, (size_t) filesize, PROT_READ, MAP_PRIVATE, fd, 0);

    if (close(fd) == -1) {
        printerr(module, strerror(errno), key_filename);
        return -1;
    }

    map->addr = memblock;
    map->filesize = (size_t) filesize;

    return 0;
}

int destroy_key_map(struct mapconf_t *map)
{
    if (munmap(map->addr, map->filesize) == -1) {
        printerr(module, strerror(errno), "munmap");
    }
    return 0;
}

int encrypt_files(const char *plaintext_dirpath, int depth, const char *ciphertext_dirpath,
    struct mapconf_t *key_map, long max_running_threads)
{
    DIR *currdir;
    if (!(currdir = opendir(plaintext_dirpath))) {
        printerr(module, strerror(errno), plaintext_dirpath);
        return 1;
    }

    struct dirent *cdirent;
    while (cdirent = readdir(currdir)) {
        if (!strcmp(".", cdirent->d_name) || !strcmp("..", cdirent->d_name)) {
            continue;
        }

        char explored_path[PATH_MAX];
        create_filepath(explored_path, plaintext_dirpath, cdirent->d_name);
        if (depth && isdir(explored_path)) {
            char new_ciphertext_dirpath[PATH_MAX];
            create_filepath(new_ciphertext_dirpath, ciphertext_dirpath, cdirent->d_name);
            encrypt_files(explored_path, depth - 1, new_ciphertext_dirpath, key_map, max_running_threads);
        } else if (isreg(explored_path)) {
            long tindex = wait_for_thread(threads, max_running_threads);
            enum tstatus_t last_status = threads[tindex].thread_status;
            threads[tindex].thread_status = ST_NULL;
            if (last_status != ST_NULL) {
                if (pthread_join(threads[tindex].thread_id, NULL) == -1) {
                    printerr(module, strerror(errno), "pthread_join");
                    return 1;
                }
            }
            char ciphertext_filepath[PATH_MAX];
            create_filepath(ciphertext_filepath, ciphertext_dirpath, cdirent->d_name);

            struct encrypter_params_t *params = malloc(sizeof(struct encrypter_params_t));
            realpath(explored_path, params->plaintext_filepath);
            realpath(ciphertext_filepath, params->ciphertext_filepath);
            params->map = key_map;
            params->thread_status = &threads[tindex].thread_status;

            if (pthread_create(&threads[tindex].thread_id, NULL, &encryption_worker, params) == -1) {
                printerr(module, strerror(errno), "pthread_create");
                free(params);
                return 1;
            }
            threads[tindex].thread_status = ST_BUSY;
        }
    }

    if (closedir(currdir) == -1) {
        printerr(module, strerror(errno), plaintext_dirpath);
    }
    return 0;
}

void *encryption_worker(void *args)
{
    struct encrypter_params_t *params = (struct encrypter_params_t *) args;

    int source_fd;
    if (source_fd = open(params->plaintext_filepath, O_RDONLY), source_fd == -1) {
        printerr(module, strerror(errno), params->plaintext_filepath);
        goto free_thread;
    }

    int dest_fd;
    if (dest_fd = open(params->ciphertext_filepath, O_CREAT | O_WRONLY, 0777), dest_fd == -1) {
        printerr(module, strerror(errno), params->ciphertext_filepath);
        goto free_thread;
    }

    uint8_t block[BLOCK_SIZE];
    long long keypos = 0;
    ssize_t rdbytes;
    bool is_rdwrerror = false;
    while (!is_rdwrerror && (rdbytes = read(source_fd, block, BLOCK_SIZE))) {
        if (rdbytes != -1) {
            for (int i = 0; i < rdbytes; i++) {
                block[i] = block[i] ^ get_key_byte(params->map, &keypos);
            }
            if (write(dest_fd, block, (size_t) rdbytes) == -1) {
                printerr(module, strerror(errno), params->ciphertext_filepath);
                is_rdwrerror = true;
            }
        } else {
            printerr(module, strerror(errno), params->plaintext_filepath);
            is_rdwrerror = true;
        }
    }

free_thread:
    /* Dobby is free! */
    *params->thread_status = ST_FREE;
    while (*params->thread_status != ST_NULL) {
        /* block */
    }
    free(params);

    return NULL;
}

uint8_t get_key_byte(struct mapconf_t *map, long long *pos)
{
    if (*pos >= map->filesize) {
        *pos = 0;
    }

    uint8_t *addr = (uint8_t *)map->addr;
    return addr[(*pos)++];
}