#ifndef HTTP_MSG_H
#define HTTP_MSG_H

#include <stdbool.h>

#include "buffer.h"

#define MAX_HEADERS 64
#define MAX_HEADER_FIELD 256
#define MAX_HEADER_VALUE 1024
#define MAX_URL_LEN 1024

typedef struct {
    char field[MAX_HEADER_FIELD];
    char value[MAX_HEADER_VALUE];
} header_t;

typedef struct {
    const char *end_pos;

    int method;      // Only for requests
    int status;      // Only for responses

    char url[MAX_URL_LEN];
    size_t url_len;

    header_t headers[MAX_HEADERS];
    int num_headers;

    char *body;
    size_t body_len;
    size_t body_cap;
} http_message_t;

void Http_Msg_free(http_message_t *msg);
void Http_Msg_p_free(http_message_t **msg);
Buffer assemble_http_message(const http_message_t *msg);
void inject_http_header(http_message_t *msg, char *field, char *value);
void hijack_http_header(http_message_t *msg, char *old_field, char *new_field, char *value);
bool Http_Msg_has(http_message_t *msg, char *field, char *value);
char *Http_Msg_get_value(http_message_t *msg, char *field);
char *get_host_and_port(const http_message_t *msg, int *port);
http_message_t* Http_Msg_deep_copy(const http_message_t* src);
void init_parser(llhttp_t *parser, llhttp_settings_t *settings, http_message_t *msg);

#endif