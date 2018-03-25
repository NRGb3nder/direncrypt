#ifndef DIRENCRYPT_PTHREAD_ROUTINES_H
#define DIRENCRYPT_PTHREAD_ROUTINES_H

#include <stdbool.h>
#include <pthread.h>

enum tstatus_t {
    ST_NULL,
    ST_FREE,
    ST_BUSY,
    ST_REFRESHED
};

struct tconf_t {
    pthread_t thread_id;
    enum tstatus_t thread_status;
    void *args;
};

long wait_for_thread(struct tconf_t *threads, long threads_num);
bool are_finished_threads(struct tconf_t *threads, long threads_num);

#endif //DIRENCRYPT_PTHREAD_ROUTINES_H
