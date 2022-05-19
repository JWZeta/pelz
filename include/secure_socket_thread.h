#ifndef INCLUDE_SECURE_SOCKET_THREAD_H_
#define INCLUDE_SECURE_SOCKET_THREAD_H_

#include <pthread.h>

typedef struct
{
  int socket_id;
  int max_requests;
  pthread_mutex_t lock;
} ThreadArgs;

/**
 * <pre>
 * Function executed on generation of secure socket to listen for connections
 * <pre>
 *
 * @param[in] arg a pointer to a structure containing the
 *                socket id for that thread and the key table
 *                mutex.
 *
 * @return none
 */
void secure_socket_thread(void *arg);

/**
 * <pre>
 * Function executed on each thread generated by connection to secure socket
 * <pre>
 * 
 * @param[in] arg a pointer to a structure containing the 
 *                socket id for that thread and the key table
 *                mutex.
 *
 * @return none
 */
void secure_socket_process(void *arg);

#endif
