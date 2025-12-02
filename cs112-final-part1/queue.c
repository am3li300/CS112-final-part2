/*
Only built to store Buffers
Queue takes ownership of buffers after getting them
*/

#include <assert.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include "queue.h"
#include "buffer.h"

typedef struct Node {
    Buffer value;
    struct Node *next;
} *Node;

struct Queue {
    Node front;
    Node back;
    int size;
};

Queue Queue_new()
{
    Queue queue = malloc(sizeof(struct Queue));
    assert(queue != NULL);
    queue->front = NULL;
    queue->back = NULL;
    queue->size = 0;

    return queue;
}

void Queue_free(Queue *queue)
{
    assert(queue != NULL);
    assert(*queue != NULL);

    int size = (*queue)->size;

    for (int i = 0; i < size; i++) {
        Queue_pop(*queue);
    }

    free(*queue);
    *queue = NULL;
}

void Queue_push(Queue queue, Buffer value)
{
    assert(queue != NULL);
    assert(value != NULL);

    Node new_node = malloc(sizeof(struct Node));
    assert(new_node != NULL);

    new_node->value = value;// Buffer_new(Buffer_content(value), Buffer_size(value));
    
    new_node->next = NULL;

    if (queue->size == 0) {
        queue->front = new_node;
        queue->back = new_node;
    }
    else {
        queue->back->next = new_node;
        queue->back = new_node;
    }

    queue->size++;
}

void Queue_pop(Queue queue)
{
    assert(queue != NULL);

    if (queue->size > 0) {
        Node new_front = queue->front->next;

        Buffer_free(&(queue->front->value));
        free(queue->front);

        queue->front = new_front;
        queue->size--;
    }
}

Buffer Queue_peek(Queue queue)
{
    assert(queue != NULL);

    if (queue->size == 0) {
        return NULL;
    }
    else {
        return queue->front->value;
    }
}

bool Queue_empty(Queue queue)
{
    assert(queue != NULL);
    return queue->size == 0;
}