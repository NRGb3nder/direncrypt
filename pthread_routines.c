#include "pthread_routines.h"

long wait_for_thread(struct tconf_t *threads, long threads_num)
{
    long i = 0;
    while (true) {
        if (threads[i].thread_status != ST_BUSY) {
            return i;
        }
        i = (i == threads_num - 1) ? 0 : i + 1;
    }
}

bool are_finished_threads(struct tconf_t *threads, long threads_num) {
    for (long i = 0; i < threads_num; i++) {
        if (threads[i].thread_status == ST_BUSY) {
            return false;
        }
    }
    return true;
}