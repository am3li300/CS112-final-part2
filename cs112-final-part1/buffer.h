#ifndef BUFFER_H
#define BUFFER_H

typedef struct Buffer *Buffer;

Buffer Buffer_new(char *arr, unsigned int size);
void Buffer_free(Buffer *buffer);
char *Buffer_content(Buffer buffer);
int Buffer_size(Buffer buffer);
int Buffer_consumed(Buffer buffer);
void Buffer_set_consumed(Buffer buffer, int consumed);

#endif