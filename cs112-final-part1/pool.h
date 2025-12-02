#ifndef POOL_H
#define POOL_H

#include <sys/select.h>

typedef struct Pool *Pool;

Pool Pool_new(int fd);
void Pool_add_write(Pool pool, int fd);
void Pool_add_read(Pool pool, int fd);
void Pool_remove_write(Pool pool, int fd);
void Pool_remove(Pool pool, int fd);
void Pool_reset(Pool pool);
int Pool_needs_write(Pool pool, int fd1, int fd2);
fd_set *Pool_read_fds(Pool pool);
fd_set *Pool_write_fds(Pool pool);
int Pool_nfds(Pool pool);

#endif