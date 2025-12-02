#ifndef PARTY_H
#define PARTY_H

#include "http_msg.h"
#include <openssl/ssl.h>
#include <stdbool.h>

typedef enum {
    ERROR,
    PARTIAL,
    DONE // on read this means message complete, on write this means queue empty
} Return;

typedef struct Party *Party;

Party Party_new(int fd);
void Party_free(Party *party);
int Party_get_fd(Party party);
void Party_set_fd(Party party, int fd);
SSL *Party_get_ssl(Party party);
void Party_set_ssl(Party party, SSL_CTX *ctx);
http_message_t *Party_get_read(Party party);
void Party_push_write(Party party, Buffer msg);
int Party_read(Party party, bool override);
int Party_write(Party party, bool override);


#endif