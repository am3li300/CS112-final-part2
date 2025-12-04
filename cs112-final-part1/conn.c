#include <openssl/ssl.h>
#include <openssl/evp.h>
#include <openssl/asn1.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/err.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdbool.h>
#include <stdlib.h>
#include <assert.h>
#include "llhttp.h"
#include <stdio.h>

#include "conn.h"
#include "party.h"
#include "http_msg.h"
#include "vec.h"

#define CERT_TTL 365 // in days

#define HTTP_DEFAULT_PORT 80
#define HTTPS_DEFAULT_PORT 443

#define HTTP_200_CONNECTION_ESTABLISHED \
    "HTTP/1.1 200 Connection Established\r\n" \
    "X-Proxy:CS112\r\n" \
    "\r\n"

#define ID_FIELD "Client-ID"

typedef enum {
    STANDARD,
    CONNECT,
    CLIENT_HANDSHAKE,
    SERVER_HANDSHAKE
} Status;

struct Conn {
    int id;
    Party server;
    Party client;
    Status status;
    Type type;
    unsigned long last_active;
    Party LLM;
};

/*
-need to add client id to each connection
-make the llm a special connection with only client, status standard, type llm
-llm guaranteed to be connection index 0, so pass it in server_read, after server read done, parse for content-type html, if that exists push write to llm, else, push write to client
-for conn_read llm, standard, if done and if type == llm, parse client id, find connection in list, push write to them
-for conn_write llm, just standard
-lowk pass the vector pointer to conn_read
*/

Conn Conn_new(int client_fd, unsigned long curr_time, Type type, int id)
{
    Conn conn = malloc(sizeof(struct Conn));
    assert(conn != NULL);

    conn->id = id;
    conn->client = Party_new(client_fd);
    conn->server = Party_new(-1);
    conn->status = STANDARD;
    conn->type = type;
    conn->last_active = curr_time;

    return conn;
}

void Conn_free(Conn *conn)
{
    assert(conn != NULL);
    assert(*conn != NULL);

    Party_free(&((*conn)->client));
    Party_free(&((*conn)->server));

    free(*conn);
    *conn = NULL;
}

int set_nonblocking1(int fd) {
    int flags;

    // Get the current flags
    flags = fcntl(fd, F_GETFL, 0);
    if (flags == -1) {
        perror("fcntl(F_GETFL)");
        return -1;
    }

    // Add the O_NONBLOCK flag
    flags |= O_NONBLOCK;

    // Set the new flags
    if (fcntl(fd, F_SETFL, flags) == -1) {
        perror("fcntl(F_SETFL)");
        return -1;
    }

    return 0; // Success
}

void make_cert(X509 **x, EVP_PKEY **pkey, 
               char *hostname, X509 *CA_cert, EVP_PKEY *CA_pkey, 
               EVP_PKEY_CTX *pkey_ctx, unsigned long curr_time)
{
    assert(EVP_PKEY_keygen(pkey_ctx, pkey) > 0);
    X509_set_version(*x, 2);

    ASN1_INTEGER_set(X509_get_serialNumber(*x), rand());
    X509_gmtime_adj(X509_get_notBefore(*x), 0);
    X509_gmtime_adj(X509_get_notAfter(*x), 60 * 60 * 24 * CERT_TTL);
    assert(X509_set_pubkey(*x, *pkey) > 0);
    assert(X509_set_issuer_name(*x, X509_get_subject_name(CA_cert)) > 0);

    X509_NAME *name = X509_NAME_new();
    assert(X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (const unsigned char *)hostname, -1, -1, 0) > 0);
    assert(X509_set_subject_name(*x, name) > 0);


    GENERAL_NAMES *gens = GENERAL_NAMES_new();
    GENERAL_NAME *gen = GENERAL_NAME_new();

    /* Set type = dNSName */
    ASN1_IA5STRING *ia5 = ASN1_IA5STRING_new();
    ASN1_STRING_set(ia5, hostname, strlen(hostname));

    GENERAL_NAME_set0_value(gen, GEN_DNS, ia5);
    sk_GENERAL_NAME_push(gens, gen);

    /* Wrap in proper extension */
    X509_EXTENSION *san = X509V3_EXT_i2d(NID_subject_alt_name, 0, gens);
    GENERAL_NAMES_free(gens);
    X509_add_ext(*x, san, -1);


    assert(X509_sign(*x, CA_pkey, EVP_sha256()) > 0);

    // FILE *f = fopen("my_cert.pem", "w");
    // PEM_write_X509(f, *x);
    // fclose(f);
}

int connect_to_server(const char *hostname, int port)
{
    struct sockaddr_in saddr;
    struct hostent *h = gethostbyname(hostname);
    memset(&saddr, '\0', sizeof(saddr));
    saddr.sin_family = AF_INET;
    memcpy((char *) &saddr.sin_addr.s_addr, h->h_addr_list[0], h->h_length); // copy the address
    saddr.sin_port = htons(port);

    int s_fd = socket(AF_INET, SOCK_STREAM, 0);
    assert(connect(s_fd, (struct sockaddr *) &saddr, sizeof(saddr)) == 0);

    printf("Connected to %s on port %d\n", hostname, port);

    return s_fd;
}

void set_up_server(Conn conn, int port, http_message_t *msg, Pool pool, unsigned long curr_time,
                   SSL_CTX *as_server_ctx, SSL_CTX *as_client_ctx, X509 *CA_cert, 
                   EVP_PKEY *CA_pkey, EVP_PKEY_CTX *pkey_ctx)
{
    char *hostname = get_host_and_port(msg, &port);
    int s_fd = connect_to_server(hostname, port);
    assert(set_nonblocking1(s_fd) == 0);

    Party_set_fd(conn->server, s_fd);
    Pool_add_read(pool, s_fd);

    if (conn->type == HTTPS) {
        Party server = conn->server;
        Party client = conn->client;

        Party_set_ssl(server, as_client_ctx);
        Party_set_ssl(client, as_server_ctx);
        X509 *x = X509_new();
        EVP_PKEY *pkey = NULL;
        make_cert(&x, &pkey, hostname, CA_cert, CA_pkey, pkey_ctx, curr_time);
        SSL_use_certificate(Party_get_ssl(client), x);
        SSL_use_PrivateKey(Party_get_ssl(client), pkey);
    }

    free(hostname);
}

int TLS_handshake(Conn conn, SSL *ssl, int fd, int (*SSL_handshake)(SSL *), Status status, Pool pool)
{
    int res = SSL_handshake(ssl);
    if (res == 1) {
        if (status == STANDARD)
            printf("Server TLS handshake complete\n");
        else if (status == SERVER_HANDSHAKE)
            printf("Client TLS handshake complete\n");
        conn->status = status;
        Pool_remove_write(pool, fd);
        return DONE;
    }
    else {
        int err = SSL_get_error(ssl, res);
        if (err != SSL_ERROR_NONE && err != SSL_ERROR_WANT_READ && err != SSL_ERROR_WANT_WRITE) {
            const char *err_str = ERR_reason_error_string(ERR_get_error());
            if (status == STANDARD) {
                printf("Error with Server TLS handshake: %s", err_str);
            }
            else if (status == SERVER_HANDSHAKE) {
                printf("Error with Client TLS handshake: %s", err_str);
            }
            if (strcmp(err_str, "ssl/tls alert bad certificate") == 0) {
                char buf[100];
                X509_NAME_get_text_by_NID(X509_get_subject_name(SSL_get_certificate(ssl)), 13, buf, 100);
                printf(" for host %s", buf);
            }
            printf("\n");
            return ERROR;
        }
    }

    return PARTIAL;
}

// 0 for error, > 0 success
int Conn_client_read(Conn conn, Pool pool, unsigned long curr_time, 
                     SSL_CTX *as_server_ctx, SSL_CTX *as_client_ctx, X509 *CA_cert, 
                     EVP_PKEY *CA_pkey, EVP_PKEY_CTX *pkey_ctx, FILE *f, vec_void_t *traffic)
{
    conn->last_active = curr_time;
    Party client = conn->client;
    int res = ERROR;
    Status status = conn->status;
    if (status == STANDARD) {
        res = Party_read(client, false);
        if (res == ERROR)
            return ERROR;
        else if (res == DONE) {
            http_message_t *msg = Party_get_read(client);
            if (conn->type == LLM) {
                Buffer response = assemble_http_message(msg);

                assert(fwrite("READ FROM LLM SERVER\n", 1, strlen("READ FROM LLM SERVER\n"), f) != 0);
                assert(fwrite(Buffer_content(request), 1, Buffer_size(request), f) != 0);
                assert(fwrite("\n\n", 1, 2, f) != 0);
                fflush(f);

                char *id_str = Http_Msg_get_field(msg, ID_FIELD);
                int id = strtol(id_str, NULL, 10);
                Conn client = NULL;
                for (int i = 0; i < traffic->length; i++) {
                    if (traffic->data[i]->id == id) {
                        client = traffic->data[i];
                        break;
                    }
                }
                if (client == NULL) {
                    printf("Client %d not found\n", id);
                    return PARTIAL; // do not want to return error since we don't want to kick off the LLM connection
                }

                Party_push_write(client->client, response);
                Pool_add_write(pool, Party_get_fd(client->client));
                return DONE;
            }
            else if (conn->type == HTTP && msg->method == HTTP_CONNECT) {
                Buffer request = assemble_http_message(msg);
                assert(fwrite("READ CONNECT FROM CLIENT\n", 1, strlen("READ CONNECT FROM CLIENT\n"), f) != 0);
                assert(fwrite(Buffer_content(request), 1, Buffer_size(request), f) != 0);
                assert(fwrite("\n\n", 1, 2, f) != 0);
                fflush(f);
                Buffer_free(&request);


                conn->status = CONNECT;
                conn->type = HTTPS;
                set_up_server(conn, HTTPS_DEFAULT_PORT, msg, pool, 
                                curr_time, as_server_ctx, as_client_ctx, 
                                CA_cert, CA_pkey, pkey_ctx);
                Buffer response = Buffer_new(HTTP_200_CONNECTION_ESTABLISHED, strlen(HTTP_200_CONNECTION_ESTABLISHED));

                Party_push_write(client, response);
                Pool_add_write(pool, Party_get_fd(client));
                return DONE;
            }
            else if (conn->type == HTTP && msg->method == HTTP_GET) {
                set_up_server(conn, HTTP_DEFAULT_PORT, msg, pool,
                                0, NULL, NULL, NULL, NULL, NULL);
            }

            Buffer request = assemble_http_message(msg);


            assert(fwrite("READ FROM CLIENT\n", 1, strlen("READ FROM CLIENT\n"), f) != 0);
            assert(fwrite(Buffer_content(request), 1, Buffer_size(request), f) != 0);
            assert(fwrite("\n\n", 1, 2, f) != 0);
            fflush(f);

            Party_push_write(conn->server, request);
            Pool_add_write(pool, Party_get_fd(conn->server));
            return DONE;
        }
    }
    else if (status == CLIENT_HANDSHAKE) {
        res = TLS_handshake(conn, Party_get_ssl(client), Party_get_fd(client), SSL_accept, SERVER_HANDSHAKE, pool);
        if (res == ERROR)
            return ERROR;
    }
    else if (status == SERVER_HANDSHAKE)
        return PARTIAL; // do nothing while we wait to handshake with server

    if (res == ERROR)
        printf("Client read status control flow error\n");

    return res;
}

int Conn_client_write(Conn conn, Pool pool, unsigned long curr_time)
{
    conn->last_active = curr_time;
    Party client = conn->client;
    Status status = conn->status;
    int res = ERROR;
    if (status == STANDARD) {
        res = Party_write(client, false);
        if (res == ERROR)
            return ERROR;
        else if (res == DONE) {
            Pool_remove_write(pool, Party_get_fd(client));
            if (conn->type == HTTP){
                printf("HTTP client done\n");
                return ERROR;
            }
        }
    }
    else if (status == CONNECT) {
        res = Party_write(client, true);
        if (res == ERROR)
            return ERROR;
        else if (res == DONE) {
            printf("Sent client 200 Connection Established\n");
            Pool_add_write(pool, Party_get_fd(conn->server));
            conn->status = CLIENT_HANDSHAKE;
            return DONE;
        }
    }
    else if (status == CLIENT_HANDSHAKE) {
        res = TLS_handshake(conn, Party_get_ssl(client), Party_get_fd(client), SSL_accept, SERVER_HANDSHAKE, pool);
        if (res == ERROR)
            return ERROR;
    }
    else if (status == SERVER_HANDSHAKE)
        return PARTIAL; // do nothing while we wait to handshake with server

    if (res == ERROR)
        printf("Client write status control flow error\n");

    return res;
}

int Conn_server_read(Conn conn, Pool pool, unsigned long curr_time, FILE *f, Conn LLM)
{
    conn->last_active = curr_time;
    Party server = conn->server;
    int res = ERROR;
    Status status = conn->status;

    if (status == STANDARD) {
        res = Party_read(server, false);
        if (res == ERROR)
            return ERROR;
        else if (res == DONE) {
            http_message_t *msg = Party_get_read(server);
            inject_http_header(msg, "X-Proxy", "CS112");
            char buf[10];
            inject_http_header(msg, ID_FIELD, snprintf(buf, 10, "%d", conn->id));

            Buffer response = assemble_http_message(msg);

            fwrite("READ FROM SERVER\n", 1, strlen("READ FROM SERVER\n"), f);
            fwrite(Buffer_content(response), 1, Buffer_size(response), f);
            fwrite("\n\n", 1, 2, f);
            fflush(f);

            if (Http_Msg_has(msg, "content-type", "text/html")) {
                Party_push_write(LLM->client, response);
                Pool_add_write(pool, Party_get_fd(LLM->client));
            }
            else {
                Party_push_write(conn->client, response);
                Pool_add_write(pool, Party_get_fd(conn->client));
            }

            return DONE;
        }
    }
    else if (status == SERVER_HANDSHAKE) {
        res = TLS_handshake(conn, Party_get_ssl(server), Party_get_fd(server), SSL_connect, STANDARD, pool);
        if (res == ERROR)
            return ERROR;
    }
    else if (status == CLIENT_HANDSHAKE)
        return PARTIAL; // do nothing while we wait to handshake with client

    if (res == ERROR)
        printf("Server read status control flow error\n");

    return res;
}

int Conn_server_write(Conn conn, Pool pool, unsigned long curr_time) 
{
    conn->last_active = curr_time;
    Party server = conn->server;
    int res = ERROR;
    Status status = conn->status;
    if (status == STANDARD) {
        res = Party_write(server, false);
        if (res == ERROR)
            return ERROR;
        else if (res == DONE)
            Pool_remove_write(pool, Party_get_fd(server));
    }
    else if (status == SERVER_HANDSHAKE) {
        res = TLS_handshake(conn, Party_get_ssl(server), Party_get_fd(server), SSL_connect, STANDARD, pool);
        if (res == ERROR)
            return ERROR;
    }
    else if (status == CLIENT_HANDSHAKE)
        return PARTIAL; // do nothing while we wait to handshake with client

    if (res == ERROR)
        printf("Server write status control flow error\n");

    return res;
}

int Conn_get_server_fd(Conn conn)
{
    assert(conn != NULL);
    return Party_get_fd(conn->server);
}

int Conn_get_client_fd(Conn conn)
{
    assert(conn != NULL);
    return Party_get_fd(conn->client);
}

unsigned long Conn_get_last_active(Conn conn)
{
    assert(conn != NULL);
    return conn->last_active;
}

