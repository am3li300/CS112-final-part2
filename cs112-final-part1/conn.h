#ifndef CONN_H
#define CONN_H

#include "pool.h"
#include "vec.h"
#include <openssl/ssl.h>

typedef struct Conn *Conn;

typedef enum {
    LLM,
    HTTP,
    HTTPS
} Type;

Conn Conn_new(int client_fd, unsigned long curr_time, Type type, int id);
void Conn_free(Conn *conn);
int Conn_client_read(Conn conn, Pool pool, unsigned long curr_time, 
                     SSL_CTX *as_server_ctx, SSL_CTX *as_client_ctx, X509 *CA_cert, 
                     EVP_PKEY *CA_pkey, EVP_PKEY_CTX *pkey_ctx, FILE *f, vec_void_t *traffic);
int Conn_client_write(Conn conn, Pool pool, unsigned long curr_time);
int Conn_server_read(Conn conn, Pool pool, unsigned long curr_time, FILE *f, Conn LLM);
int Conn_server_write(Conn conn, Pool pool, unsigned long curr_time);
int Conn_get_server_fd(Conn conn);
int Conn_get_client_fd(Conn conn);
unsigned long Conn_get_last_active(Conn conn);

#endif