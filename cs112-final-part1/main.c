#include <openssl/ssl.h>
#include <openssl/evp.h>
#include <openssl/asn1.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <stdio.h>
#include <assert.h>
#include <time.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <fcntl.h>
#include <arpa/inet.h>

#include "vec.h"
#include "conn.h"
#include "pool.h"

#define TIMEOUT 15 * 60 // 15 minutes in seconds

unsigned long curr_time(struct timespec *ts)
{
    assert(timespec_get(ts, TIME_UTC) != 0);
    return ts->tv_sec;
}

int set_nonblocking(int fd) {
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

int set_up_socket(unsigned short port)
{
    struct sockaddr_in addr;
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    assert(fd >= 0);

    assert(set_nonblocking(fd) == 0);

    int optval = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (const void *)&optval , sizeof(int));

    memset(&addr, '\0', sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(port); 

    assert(bind(fd, (struct sockaddr *)&addr, sizeof(addr)) >= 0);
    assert(listen(fd, 5) == 0);

    return fd;
}

void configure_ctx(SSL_CTX *c_ctx, SSL_CTX *s_ctx)
{
    // if (!SSL_CTX_set_min_proto_version(c_ctx, TLS1_2_VERSION) || !SSL_CTX_set_min_proto_version(s_ctx, TLS1_2_VERSION)) {
    //     SSL_CTX_free(s_ctx);
    //     SSL_CTX_free(c_ctx);
    //     printf("Failed to set the minimum TLS protocol version\n");
    //     exit(1);
    // }

    SSL_CTX_set_verify(c_ctx, SSL_VERIFY_NONE, NULL);
}

void read_CA_cert(X509 **CA_cert, EVP_PKEY **CA_pkey, char *crt_path, char *key_path)
{
    FILE *crt = fopen(crt_path, "r");
    FILE *key = fopen(key_path, "r");
    assert(crt != NULL);
    assert(key != NULL);

    *CA_cert = PEM_read_X509(crt, NULL, NULL, NULL);
    *CA_pkey = PEM_read_PrivateKey(key, NULL, NULL, NULL);

    assert(*CA_cert != NULL);
    assert(*CA_pkey != NULL);

    fclose(crt);
    fclose(key);
}

void accept_client(Pool pool, int main_fd, vec_void_t *traffic, struct timespec *ts, int *ID)
{
    struct sockaddr_in c_addr;
    int c_len = sizeof(c_addr);
    int c_sd = accept(main_fd, (struct sockaddr *)&c_addr, (socklen_t *)&c_len);
    assert(c_sd >= 0);
    assert(set_nonblocking(c_sd) == 0);
    printf("Accepted new client\n");

    Pool_add_read(pool, c_sd);

    Conn new_conn = Conn_new(c_sd, curr_time(ts), HTTP, *ID);
    (*ID)++;

    vec_push(traffic, new_conn);
}

void disconnect(Pool pool, Conn conn)
{
    int c_fd = Conn_get_client_fd(conn);
    int s_fd = Conn_get_server_fd(conn);

    if (Pool_needs_write(pool, c_fd, s_fd)) 
        return;

    Conn_free(&conn);
    Pool_remove(pool, c_fd);
    Pool_remove(pool, s_fd);
    close(c_fd);
    close(s_fd);
}

void read_write_traffic(Pool pool, vec_void_t *traffic, SSL_CTX *as_server_ctx, 
                        SSL_CTX *as_client_ctx, X509 *CA_cert, EVP_PKEY *CA_pkey, 
                        EVP_PKEY_CTX *pkey_ctx, struct timespec *ts, FILE *f)
{
    int size = traffic->length;
    fd_set *read_fds = Pool_read_fds(pool);
    fd_set *write_fds = Pool_write_fds(pool);

    for (int i = 0; i < size; i++) {
        Conn conn = traffic->data[i];
        int c_fd = Conn_get_client_fd(conn);
        int s_fd = Conn_get_server_fd(conn);
        unsigned long time = curr_time(ts);
        int res;

        if (FD_ISSET(c_fd, read_fds)) {
            res = Conn_client_read(conn, pool, time, as_server_ctx,
                                   as_client_ctx, CA_cert, CA_pkey, pkey_ctx, f, traffic);
            if (res == 0) {
                if (i == 0) {
                    printf("FATAL ERROR: LLM disconnected\n");
                    exit(1);
                }
                else printf("Disconnecting: client read\n");
                vec_swapsplice(traffic, i, 1);
                disconnect(pool, conn);
                i--;
                size--;
                continue;
            }
        }
        if (FD_ISSET(c_fd, write_fds)) {
            res = Conn_client_write(conn, pool, time);
            if (res == 0) {
                if (i == 0) {
                    printf("FATAL ERROR: LLM disconnected\n");
                    exit(1);
                }
                else printf("Disconnecting: client write\n");
                vec_swapsplice(traffic, i, 1);
                disconnect(pool, conn);
                i--;
                size--;
                continue;
            }
        }
        if (FD_ISSET(s_fd, read_fds)) {
            res = Conn_server_read(conn, pool, time, f, traffic->data[0]);
            if (res == 0) {
                printf("Disconnecting: server read\n");
                vec_swapsplice(traffic, i, 1);
                disconnect(pool, conn);
                i--;
                size--;
                continue;
            }
        }
        if (FD_ISSET(s_fd, write_fds)) {
            res = Conn_server_write(conn, pool, time);
            if (res == 0) {
                printf("Disconnecting: server write\n");
                vec_swapsplice(traffic, i, 1);
                disconnect(pool, conn);
                i--;
                size--;
            }
        }
    }
}

void check_timeouts(Pool pool, vec_void_t *traffic, struct timespec *ts)
{
    int size = traffic->length;
    unsigned long time = curr_time(ts);

    // never disconnect LLM so start at 1
    for (int i = 1; i < size; i++) {
        Conn conn = traffic->data[i];

        if (time >= Conn_get_last_active(conn) + TIMEOUT) {
            printf("Disconnecting: timed out\n");
            vec_swapsplice(traffic, i, 1);
            disconnect(pool, conn);
            i--;
            size--;
        }
    }
}

void connect_to_LLM(const char *address, int port, vec_void_t *traffic)
{
    struct sockaddr_in saddr;
    struct in_addr ip_addr;
    struct hostent *h;

    assert(inet_pton(AF_INET, address, &ip_addr) > 0);
    h = gethostbyaddr(&ip_addr, sizeof(ip_addr), AF_INET);
    assert(h != NULL);
    
    memset(&saddr, '\0', sizeof(saddr));
    saddr.sin_family = AF_INET;
    memcpy((char *) &saddr.sin_addr.s_addr, h->h_addr_list[0], h->h_length); // copy the address
    saddr.sin_port = htons(port);

    int s_fd = socket(AF_INET, SOCK_STREAM, 0);
    assert(connect(s_fd, (struct sockaddr *) &saddr, sizeof(saddr)) == 0);

    printf("Connected to %s on port %d\n", address, port);

    Conn LLM_conn = Conn_new(s_fd, 0, LLM, 0);
    vec_push(traffic, LLM_conn);
}

int main(int argc, char *argv[]) {
    assert(argc == 6);
    unsigned short port = strtol(argv[1], NULL, 10);
    char *CA_cert_path = argv[2];
    char *CA_pkey_path = argv[3];
    char *LLM_IP = argv[4];
    int LLM_port = strtol(argv[5], NULL, 10);

    int main_fd = set_up_socket(port);

    X509 *CA_cert = X509_new();
    EVP_PKEY *CA_pkey = EVP_PKEY_new();
    read_CA_cert(&CA_cert, &CA_pkey, CA_cert_path, CA_pkey_path);
    EVP_PKEY_CTX *pkey_ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    assert(EVP_PKEY_keygen_init(pkey_ctx) > 0);

    srand(time(NULL));
    struct timespec ts;
    Pool pool = Pool_new(main_fd);
    vec_void_t traffic;
    vec_init(&traffic);

    connect_to_LLM(LLM_IP, LLM_port, &traffic);

    SSL_CTX *as_client_ctx = SSL_CTX_new(TLS_client_method());
    SSL_CTX *as_server_ctx = SSL_CTX_new(TLS_server_method());
    assert(as_server_ctx != NULL && as_client_ctx != NULL);
    configure_ctx(as_client_ctx, as_server_ctx);

    FILE *f = fopen("messagelog.txt", "w");
    assert(f!=NULL);

    int ID = 1;

    printf("Set up proxy\n");

    while (1) {
        Pool_reset(pool);
        select(Pool_nfds(pool), Pool_read_fds(pool), Pool_write_fds(pool), NULL, NULL);

        read_write_traffic(pool, &traffic, as_server_ctx, as_client_ctx, CA_cert, 
                           CA_pkey, pkey_ctx, &ts, f);

        if (FD_ISSET(main_fd, Pool_read_fds(pool))) {
            accept_client(pool, main_fd, &traffic, &ts, &ID);
        }

        check_timeouts(pool, &traffic, &ts);
    }

    return 0;
}