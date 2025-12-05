#include <openssl/ssl.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <llhttp.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <assert.h>
#include <stdbool.h>

#include "party.h"
#include "http_msg.h"
#include "buffer.h"
#include "queue.h"

#define BUFSIZE 1024 * 1024 // 1 MB

struct Party {
    int fd;
    llhttp_t parser;
    llhttp_settings_t settings;
    SSL *ssl; // NULL if not an https connection

    http_message_t curr_read;

    Queue writes;
};

Party Party_new(int fd)
{
    Party party = malloc(sizeof(struct Party));
    assert(party != NULL);

    party->fd = fd;

    init_parser(&(party->parser), &(party->settings), &(party->curr_read));

    party->ssl = NULL;

    bzero(&(party->curr_read), sizeof(http_message_t));
    (party->curr_read).body_cap = BUFSIZE;
    (party->curr_read).body = malloc((party->curr_read).body_cap);
    assert((party->curr_read).body != NULL);

    // party->buf_len = 0;

    party->writes = Queue_new();

    return party;
}

void Party_free(Party *party)
{
    assert(party != NULL);
    assert(*party != NULL);

    if ((*party)->ssl != NULL) {
        SSL_free((*party)->ssl);
    }

    Http_Msg_free(&((*party)->curr_read));
    Queue_free(&((*party)->writes));

    free(*party);
    *party = NULL;
}

int Party_get_fd(Party party)
{
    assert(party != NULL);
    return party->fd;
}

void Party_set_fd(Party party, int fd)
{
    assert(party != NULL);
    party->fd = fd;
}

SSL *Party_get_ssl(Party party)
{
    assert(party != NULL);
    return party->ssl;
}

void Party_set_ssl(Party party, SSL_CTX *ctx)
{
    assert(party != NULL);
    assert(ctx != NULL);

    party->ssl = SSL_new(ctx);
    assert(party->ssl != NULL);

    SSL_set_fd(party->ssl, party->fd);

    BIO *bio = BIO_new(BIO_s_socket());
    assert(bio != NULL);
    BIO_set_fd(bio, party->fd, BIO_NOCLOSE);
    SSL_set_bio(party->ssl, bio, bio);
}

http_message_t *Party_get_read(Party party)
{
    assert(party != NULL);
    return &party->curr_read;
}

void Party_push_write(Party party, Buffer msg)
{
    assert(party != NULL);
    assert(msg != NULL);

    Queue_push(party->writes, msg);
}

int Party_read(Party party, bool override)
{
    assert(party != NULL);

    llhttp_t* parser_p = &(party->parser);

    char buf[BUFSIZE];

    // char *buf = party->buf;
    // int buf_len = party->buf_len;

    char *start = buf; // + buf_len;
    int bytes_left = BUFSIZE; // - buf_len;
    ssize_t bytes_read = 0;

    // do a read
    if (party->ssl == NULL || override) {
        bytes_read = read(party->fd, start, bytes_left);
        if (bytes_read <= 0) {
            perror("Error reading from http socket");
            return ERROR;
        }
    }
    else {
        int res = SSL_read_ex(party->ssl, start, bytes_left, (size_t *)&bytes_read);
        if (res <= 0) {
            int err = SSL_get_error(party->ssl, res);
            if (err == SSL_ERROR_WANT_READ) {
                printf("SSL read error: want read\n");
                return PARTIAL;
            }
            else if (err == SSL_ERROR_WANT_WRITE) {
                printf("SSL read error: want write\n");
                return PARTIAL;
            }
            else {
                printf("SSL read error: %s\n", ERR_error_string(err, NULL));
                return ERROR;
            }
        }
    }

    // printf("bytes read: %zu\n", bytes_read);

    if (bytes_read == 0) {
        printf("Peer socket closed\n");
        return ERROR;
    }

    // parse bytes
    // buf_len += bytes_read;
    enum llhttp_errno err = llhttp_execute(parser_p, buf, bytes_read);

    // handle leftovers
    if (err == HPE_CB_MESSAGE_COMPLETE) {
        // printf("Read complete message\n");
        const char *pos = llhttp_get_error_pos(parser_p);
        int leftover_len = (buf + bytes_read) - pos;
        if (leftover_len > 0) {
            printf("Two messages in one read with leftover len %d\n", leftover_len);
        }
        // memcpy(buf, pos, leftover_len);
        // party->buf_len = leftover_len;

        llhttp_reset(parser_p);
        return DONE;
    }
    else if (err != HPE_OK && err != HPE_PAUSED_UPGRADE) {
        if (err == HPE_INVALID_METHOD) {
            printf("\nMESSAGE\n%s\n\n\n", buf);
        }
        fprintf(stderr, "Parse error: %s %s\n", llhttp_errno_name(err), llhttp_get_error_reason(parser_p));
        return ERROR;
    }
    
    // party->buf_len = 0;
    return PARTIAL;
}

int Party_write(Party party, bool override)
{
    assert(party != NULL);

    Queue q = party->writes;
    if (Queue_empty(q))
        return DONE;

    Buffer curr_write = Queue_peek(q);
    char *buf = Buffer_content(curr_write);
    int msg_len = Buffer_size(curr_write);
    int consumed = Buffer_consumed(curr_write);
    ssize_t bytes_written = 0;

    char *start = buf + consumed;
    int bytes_left = msg_len - consumed;

    // do a write
    if (party->ssl == NULL || override) {
        bytes_written = write(party->fd, start, bytes_left);
        if (bytes_written <= 0) {
            perror("Error writing to http socket");
            return ERROR;
        }
    }
    else {
        int res = SSL_write_ex(party->ssl, start, bytes_left, (size_t *)&bytes_written);
        if (res <= 0) {
            int err = SSL_get_error(party->ssl, res);
            if (err == SSL_ERROR_WANT_READ) {
                printf("SSL read error: want read\n");
                return PARTIAL;
            }
            else if (err == SSL_ERROR_WANT_WRITE) {
                printf("SSL read error: want write\n");
                return PARTIAL;
            }
            else {
                printf("SSL write error: %s\n", ERR_error_string(err, NULL));
                return ERROR;
            }
        }
    }

    if (bytes_written == 0) {
        printf("Peer closed socket\n");
        return ERROR;
    }

    // printf("bytes written: %zu\n", bytes_written);

    consumed += bytes_written;
    Buffer_set_consumed(curr_write, consumed);
    if (consumed == msg_len) {
        // printf("Wrote complete message\n");
        Queue_pop(q);
        if (Queue_empty(q))
            return DONE;
    }

    return PARTIAL;
}