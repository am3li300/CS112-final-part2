#ifndef QUEUE_H
#define QUEUE_H

#include <stdbool.h>

#include "buffer.h"

typedef struct Queue *Queue;

Queue Queue_new();
void Queue_free(Queue *queue);
void Queue_push(Queue queue, Buffer value);
void Queue_pop(Queue queue);
Buffer Queue_peek(Queue queue);
bool Queue_empty(Queue queue);

#endif