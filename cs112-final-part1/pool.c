#include <sys/select.h>
#include <assert.h>
#include <stdlib.h>
#include <stdio.h>

#include "pool.h"

struct Pool {
    fd_set master_read_fds;
    fd_set master_write_fds;
    fd_set read_fds;
    fd_set write_fds;
    int max_fd;
};

Pool Pool_new(int fd)
{
    Pool pool = malloc(sizeof(struct Pool));
    assert(pool != NULL);

    FD_ZERO(&pool->master_read_fds);
    FD_ZERO(&pool->master_write_fds);
    FD_ZERO(&pool->read_fds);
    FD_ZERO(&pool->write_fds);

    FD_SET(fd, &pool->master_read_fds);
    pool->max_fd = fd;

    return pool;
}

void Pool_add_write(Pool pool, int fd)
{
    assert(pool != NULL);
    FD_SET(fd, &pool->master_write_fds);
}

void Pool_add_read(Pool pool, int fd)
{
    assert(pool != NULL);
    FD_SET(fd, &pool->master_read_fds);

    if (fd > pool->max_fd) {
        pool->max_fd = fd;
    }
}

void Pool_remove_write(Pool pool, int fd)
{
    assert(pool != NULL);
    FD_CLR(fd, &pool->master_write_fds);
}

void Pool_remove(Pool pool, int fd)
{
    assert(pool != NULL);
    FD_CLR(fd, &pool->master_write_fds);
    FD_CLR(fd, &pool->master_read_fds);

    if (fd == pool->max_fd) {
        for (int i = fd; i >= 0; i--) {
            if (FD_ISSET(i, &pool->master_read_fds)) {
                pool->max_fd = i;
                break;
            }
        }
    }
}

void Pool_reset(Pool pool)
{
    assert(pool != NULL);
    FD_ZERO(&pool->read_fds);
    FD_ZERO(&pool->write_fds);
    pool->read_fds = pool->master_read_fds;
    pool->write_fds = pool->master_write_fds;
}

int Pool_needs_write(Pool pool, int fd1, int fd2)
{
    assert(pool != NULL);
    return (FD_ISSET(fd1, &pool->master_write_fds) || FD_ISSET(fd2, &pool->master_write_fds));
}

fd_set *Pool_read_fds(Pool pool)
{
    assert(pool != NULL);
    return &pool->read_fds;
}

fd_set *Pool_write_fds(Pool pool)
{
    assert(pool != NULL);
    return &pool->write_fds;
}

int Pool_nfds(Pool pool)
{
    assert(pool != NULL);
    return pool->max_fd + 1;
}
