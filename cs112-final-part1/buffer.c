/*
buffer owns its content, does not take ownership of what is passed to it
*/

#include <stdlib.h>
#include <assert.h>
#include <string.h>

#include "buffer.h"

struct Buffer {
    char *content;
    unsigned int size;
    unsigned int consumed;
};

Buffer Buffer_new(char *arr, unsigned int size) 
{
    Buffer buffer = malloc(sizeof(struct Buffer));
    assert(buffer != NULL);

    char *my_arr = malloc(size);
    assert(my_arr != NULL);
    memcpy(my_arr, arr, size);

    buffer->content = my_arr;
    buffer->size = size;
    buffer->consumed = 0;

    return buffer;
}

void Buffer_free(Buffer *buffer_p) 
{
    assert(buffer_p != NULL);
    assert(*buffer_p != NULL);

    free((*buffer_p)->content);

    free(*buffer_p);
    *buffer_p = NULL;
}

char *Buffer_content(Buffer buffer) 
{
    assert(buffer != NULL);
    return buffer->content;
}

int Buffer_size(Buffer buffer)
{
    assert(buffer != NULL);
    return buffer->size;
}

int Buffer_consumed(Buffer buffer)
{
    assert(buffer != NULL);
    return buffer->consumed;
}

void Buffer_set_consumed(Buffer buffer, int consumed)
{
    assert(buffer != NULL);
    buffer->consumed = consumed;
}