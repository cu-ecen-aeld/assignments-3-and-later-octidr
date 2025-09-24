#include "threading.h"
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>

// Optional: use these functions to add debug or error prints to your application
#define DEBUG_LOG_ENABLED 0
#if DEBUG_LOG_ENABLED
#define DEBUG_LOG(msg,...) printf("threading: " msg "\n" , ##__VA_ARGS__)
#else
#define DEBUG_LOG(msg,...)
#endif

#define ERROR_LOG(msg,...) printf("threading ERROR: " msg "\n" , ##__VA_ARGS__)

void* threadfunc(void* thread_param)
{
    DEBUG_LOG("threadfunc started");
    struct thread_data* my_thread_data = (struct thread_data *) thread_param;

    // Set to false at start, true on successful completion
    my_thread_data->thread_complete_success = false;

    // Wait, obtain mutex, wait, release mutex as described by thread_data structure
    usleep(my_thread_data->wait_to_obtain_ms * 1000);
    pthread_mutex_lock(my_thread_data->mutex);
    usleep(my_thread_data->wait_to_release_ms * 1000);
    pthread_mutex_unlock(my_thread_data->mutex);

    // Indicate that thread completed successfully
    my_thread_data->thread_complete_success = true;
    DEBUG_LOG("threadfunc exiting");
    return thread_param;
}


bool start_thread_obtaining_mutex(pthread_t *thread, pthread_mutex_t *mutex,int wait_to_obtain_ms, int wait_to_release_ms)
{
    /**
     * TODO: allocate memory for thread_data, setup mutex and wait arguments, pass thread_data to created thread
     * using threadfunc() as entry point.
     *
     * return true if successful.
     *
     * See implementation details in threading.h file comment block
     */
    struct thread_data *tdata = malloc(sizeof(struct thread_data));
    if(tdata == NULL)
    {
        ERROR_LOG("Failed to allocate memory for thread_data");
        return false;
    }

    tdata->mutex = mutex;
    tdata->wait_to_obtain_ms = wait_to_obtain_ms;
    tdata->wait_to_release_ms = wait_to_release_ms;

    if(pthread_create(thread, NULL, threadfunc, tdata) != 0)
    {
        ERROR_LOG("Failed to create thread");
        free(tdata);
        return false;
    }

    return true;
}

