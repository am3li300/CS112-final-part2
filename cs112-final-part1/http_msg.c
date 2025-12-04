#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <stdio.h>
#include <stdbool.h>
#include "llhttp.h"

#include "http_msg.h"
#include "buffer.h"

#define CRLF "\r\n"
#define CRLF_LEN 2

#define HEADER_INJECTION_FIELD "X-Proxy"
#define HEADER_INJECTION_VALUE "CS112"

/* Expand body capacity if needed */
static int ensure_body_capacity(http_message_t *msg, size_t needed) {
    if (msg->body_cap >= needed)
        return 0;

    size_t newcap = msg->body_cap == 0 ? 1024 : msg->body_cap * 2;
    while (newcap < needed)
        newcap *= 2;

    char *newbody = realloc(msg->body, newcap);
    if (!newbody)
        return -1;

    msg->body = newbody;
    msg->body_cap = newcap;
    return 0;
}

/* ---------------------- CALLBACKS ---------------------- */

/* Called at the beginning of a message */
int on_message_begin(llhttp_t *parser) {
    // printf("on new message\n");
    http_message_t *msg = parser->data;

    for (int i = 0; i < msg->num_headers; i++) {
        msg->headers[i].field[0] = '\0';
        msg->headers[i].value[0] = '\0';
    }

    msg->num_headers = 0;

    msg->url_len = 0;
    if (msg->url_len < MAX_URL_LEN)
        msg->url[0] = '\0';

    msg->body_len = 0;

    return 0;
}

/* URL — may be called multiple times */
int on_url(llhttp_t *parser, const char *at, size_t length) {
    http_message_t *msg = parser->data;

    if (parser->type != HTTP_REQUEST)
        return 0;

    size_t copy = length;
    if (msg->url_len + copy >= MAX_URL_LEN)
        copy = MAX_URL_LEN - msg->url_len - 1;

    memcpy(msg->url + msg->url_len, at, copy);
    msg->url_len += copy;
    msg->url[msg->url_len] = '\0';

    return 0;
}

/* Header field—may be chunked across several calls */
int on_header_field(llhttp_t *parser, const char *at, size_t length) {
    http_message_t *msg = parser->data;

    header_t *h = &msg->headers[msg->num_headers];

    size_t cur_len = strlen(h->field);
    size_t copy = length;
    if (cur_len + copy >= MAX_HEADER_FIELD)
        copy = MAX_HEADER_FIELD - cur_len - 1;

    memcpy(h->field + cur_len, at, copy);
    h->field[cur_len + copy] = '\0';

    // printf("on_headers: flags=0x%x\n", parser->flags);

    return 0;
}

int on_header_value_complete(llhttp_t *parser) {
    http_message_t *msg = parser->data;
    msg->num_headers++;
    if (msg->num_headers >= MAX_HEADERS)
        return HPE_USER; // Too many headers

    return 0;
}

/* Header value — also possibly chunked */
int on_header_value(llhttp_t *parser, const char *at, size_t length) {
    http_message_t *msg = parser->data;
    header_t *h = &msg->headers[msg->num_headers];

    size_t cur_len = strlen(h->value);
    size_t copy = length;
    if (cur_len + copy >= MAX_HEADER_VALUE)
        copy = MAX_HEADER_VALUE - cur_len - 1;

    memcpy(h->value + cur_len, at, copy);
    h->value[cur_len + copy] = '\0';

    return 0;
}

/* Called at end of headers */
int on_headers_complete(llhttp_t *parser) {
    http_message_t *msg = parser->data;

    msg->method = parser->method;
    msg->status = parser->status_code;

    return 0;
}

int on_chunk_header(llhttp_t *parser) {
    http_message_t *msg = parser->data;

    int chunk_header_size = (sizeof(int) * 2) + 3; // want a char per 4 bits + CRLF + '\0'
    char chunk_header[chunk_header_size];
    assert(snprintf(chunk_header, chunk_header_size, "%X\r\n", parser->content_length) != 0);

    chunk_header_size = strlen(chunk_header);

    size_t needed = msg->body_len + chunk_header_size;
    if (ensure_body_capacity(msg, needed) < 0)
        return HPE_USER;
    memcpy(msg->body + msg->body_len, chunk_header, chunk_header_size);
    msg->body_len += chunk_header_size;

    return 0;
}

int on_chunk_complete(llhttp_t *parser) {
    http_message_t *msg = parser->data;

    size_t needed = msg->body_len + CRLF_LEN;
    if (ensure_body_capacity(msg, needed) < 0)
        return HPE_USER;
    memcpy(msg->body + msg->body_len, CRLF, CRLF_LEN);
    msg->body_len += CRLF_LEN;

    return 0;
}

/* Body chunk — may be called multiple times */
int on_body(llhttp_t *parser, const char *at, size_t length) {
    // printf("In on body callback\n");
    http_message_t *msg = parser->data;

    size_t needed = msg->body_len + length;
    // printf("%zu total bytes needed in body buf\n", needed);

    if (ensure_body_capacity(msg, needed) < 0)
        return HPE_USER;

    memcpy(msg->body + msg->body_len, at, length);
    msg->body_len += length;

    return 0;
}

/* Final message callback */
int on_message_complete(llhttp_t *parser) {
    return HPE_CB_MESSAGE_COMPLETE;
}


void init_parser(llhttp_t *parser, llhttp_settings_t *settings, http_message_t *msg)
{
    llhttp_settings_init(settings);

    settings->on_message_begin    = on_message_begin;
    settings->on_url              = on_url;
    settings->on_header_field     = on_header_field;
    settings->on_header_value_complete = on_header_value_complete;
    settings->on_header_value     = on_header_value;
    settings->on_headers_complete = on_headers_complete;
    settings->on_chunk_header     = on_chunk_header;
    settings->on_chunk_complete   = on_chunk_complete;
    settings->on_body             = on_body;
    settings->on_message_complete = on_message_complete;

    llhttp_init(parser, HTTP_BOTH, settings);
    parser->data = msg;
}

void Http_Msg_free(http_message_t *msg)
{
    assert(msg != NULL);

    if (msg->body != NULL) {
        free(msg->body);
    }

    msg->body = NULL;
}

void Http_Msg_p_free(http_message_t **msg)
{
    assert(msg != NULL);
    assert(*msg != NULL);

    if ((*msg)->body != NULL) {
        free((*msg)->body);
    }

    free(*msg);
    *msg = NULL;
}

static const char* llhttp_method_to_str(llhttp_method_t method) {
    switch (method) {
        case HTTP_DELETE:        return "DELETE";
        case HTTP_GET:           return "GET";
        case HTTP_HEAD:          return "HEAD";
        case HTTP_POST:          return "POST";
        case HTTP_PUT:           return "PUT";
        case HTTP_CONNECT:       return "CONNECT";
        case HTTP_OPTIONS:       return "OPTIONS";
        case HTTP_TRACE:         return "TRACE";
        default: return "UNKNOWN";
    }
}

static const char* llhttp_status_to_string(llhttp_status_t status) {
    switch (status) {

    case HTTP_STATUS_CONTINUE: return "100 Continue";
    case HTTP_STATUS_SWITCHING_PROTOCOLS: return "101 Switching Protocols";
    case HTTP_STATUS_PROCESSING: return "102 Processing";
    case HTTP_STATUS_EARLY_HINTS: return "103 Early Hints";

    case HTTP_STATUS_RESPONSE_IS_STALE: return "110 Response Is Stale";
    case HTTP_STATUS_REVALIDATION_FAILED: return "111 Revalidation Failed";
    case HTTP_STATUS_DISCONNECTED_OPERATION: return "112 Disconnected Operation";
    case HTTP_STATUS_HEURISTIC_EXPIRATION: return "113 Heuristic Expiration";
    case HTTP_STATUS_MISCELLANEOUS_WARNING: return "199 Miscellaneous Warning";

    case HTTP_STATUS_OK: return "200 OK";
    case HTTP_STATUS_CREATED: return "201 Created";
    case HTTP_STATUS_ACCEPTED: return "202 Accepted";
    case HTTP_STATUS_NON_AUTHORITATIVE_INFORMATION: return "203 Non-Authoritative Information";
    case HTTP_STATUS_NO_CONTENT: return "204 No Content";
    case HTTP_STATUS_RESET_CONTENT: return "205 Reset Content";
    case HTTP_STATUS_PARTIAL_CONTENT: return "206 Partial Content";
    case HTTP_STATUS_MULTI_STATUS: return "207 Multi-Status";
    case HTTP_STATUS_ALREADY_REPORTED: return "208 Already Reported";
    case HTTP_STATUS_TRANSFORMATION_APPLIED: return "214 Transformation Applied";
    case HTTP_STATUS_IM_USED: return "226 IM Used";
    case HTTP_STATUS_MISCELLANEOUS_PERSISTENT_WARNING: return "299 Miscellaneous Persistent Warning";

    case HTTP_STATUS_MULTIPLE_CHOICES: return "300 Multiple Choices";
    case HTTP_STATUS_MOVED_PERMANENTLY: return "301 Moved Permanently";
    case HTTP_STATUS_FOUND: return "302 Found";
    case HTTP_STATUS_SEE_OTHER: return "303 See Other";
    case HTTP_STATUS_NOT_MODIFIED: return "304 Not Modified";
    case HTTP_STATUS_USE_PROXY: return "305 Use Proxy";
    case HTTP_STATUS_SWITCH_PROXY: return "306 Switch Proxy";
    case HTTP_STATUS_TEMPORARY_REDIRECT: return "307 Temporary Redirect";
    case HTTP_STATUS_PERMANENT_REDIRECT: return "308 Permanent Redirect";

    case HTTP_STATUS_BAD_REQUEST: return "400 Bad Request";
    case HTTP_STATUS_UNAUTHORIZED: return "401 Unauthorized";
    case HTTP_STATUS_PAYMENT_REQUIRED: return "402 Payment Required";
    case HTTP_STATUS_FORBIDDEN: return "403 Forbidden";
    case HTTP_STATUS_NOT_FOUND: return "404 Not Found";
    case HTTP_STATUS_METHOD_NOT_ALLOWED: return "405 Method Not Allowed";
    case HTTP_STATUS_NOT_ACCEPTABLE: return "406 Not Acceptable";
    case HTTP_STATUS_PROXY_AUTHENTICATION_REQUIRED: return "407 Proxy Authentication Required";
    case HTTP_STATUS_REQUEST_TIMEOUT: return "408 Request Timeout";
    case HTTP_STATUS_CONFLICT: return "409 Conflict";
    case HTTP_STATUS_GONE: return "410 Gone";
    case HTTP_STATUS_LENGTH_REQUIRED: return "411 Length Required";
    case HTTP_STATUS_PRECONDITION_FAILED: return "412 Precondition Failed";
    case HTTP_STATUS_PAYLOAD_TOO_LARGE: return "413 Payload Too Large";
    case HTTP_STATUS_URI_TOO_LONG: return "414 URI Too Long";
    case HTTP_STATUS_UNSUPPORTED_MEDIA_TYPE: return "415 Unsupported Media Type";
    case HTTP_STATUS_RANGE_NOT_SATISFIABLE: return "416 Range Not Satisfiable";
    case HTTP_STATUS_EXPECTATION_FAILED: return "417 Expectation Failed";
    case HTTP_STATUS_IM_A_TEAPOT: return "418 I'm a Teapot";
    case HTTP_STATUS_PAGE_EXPIRED: return "419 Page Expired";
    case HTTP_STATUS_ENHANCE_YOUR_CALM: return "420 Enhance Your Calm";
    case HTTP_STATUS_MISDIRECTED_REQUEST: return "421 Misdirected Request";
    case HTTP_STATUS_UNPROCESSABLE_ENTITY: return "422 Unprocessable Entity";
    case HTTP_STATUS_LOCKED: return "423 Locked";
    case HTTP_STATUS_FAILED_DEPENDENCY: return "424 Failed Dependency";
    case HTTP_STATUS_TOO_EARLY: return "425 Too Early";
    case HTTP_STATUS_UPGRADE_REQUIRED: return "426 Upgrade Required";
    case HTTP_STATUS_PRECONDITION_REQUIRED: return "428 Precondition Required";
    case HTTP_STATUS_TOO_MANY_REQUESTS: return "429 Too Many Requests";
    case HTTP_STATUS_REQUEST_HEADER_FIELDS_TOO_LARGE_UNOFFICIAL: return "430 Request Header Fields Too Large (Unofficial)";
    case HTTP_STATUS_REQUEST_HEADER_FIELDS_TOO_LARGE: return "431 Request Header Fields Too Large";
    case HTTP_STATUS_LOGIN_TIMEOUT: return "440 Login Timeout";
    case HTTP_STATUS_NO_RESPONSE: return "444 No Response";
    case HTTP_STATUS_RETRY_WITH: return "449 Retry With";
    case HTTP_STATUS_BLOCKED_BY_PARENTAL_CONTROL: return "450 Blocked by Parental Control";
    case HTTP_STATUS_UNAVAILABLE_FOR_LEGAL_REASONS: return "451 Unavailable For Legal Reasons";
    case HTTP_STATUS_CLIENT_CLOSED_LOAD_BALANCED_REQUEST: return "460 Client Closed Load-Balanced Request";
    case HTTP_STATUS_INVALID_X_FORWARDED_FOR: return "463 Invalid X-Forwarded-For";
    case HTTP_STATUS_REQUEST_HEADER_TOO_LARGE: return "494 Request Header Too Large";
    case HTTP_STATUS_SSL_CERTIFICATE_ERROR: return "495 SSL Certificate Error";
    case HTTP_STATUS_SSL_CERTIFICATE_REQUIRED: return "496 SSL Certificate Required";
    case HTTP_STATUS_HTTP_REQUEST_SENT_TO_HTTPS_PORT: return "497 HTTP Request Sent to HTTPS Port";
    case HTTP_STATUS_INVALID_TOKEN: return "498 Invalid Token";
    case HTTP_STATUS_CLIENT_CLOSED_REQUEST: return "499 Client Closed Request";

    case HTTP_STATUS_INTERNAL_SERVER_ERROR: return "500 Internal Server Error";
    case HTTP_STATUS_NOT_IMPLEMENTED: return "501 Not Implemented";
    case HTTP_STATUS_BAD_GATEWAY: return "502 Bad Gateway";
    case HTTP_STATUS_SERVICE_UNAVAILABLE: return "503 Service Unavailable";
    case HTTP_STATUS_GATEWAY_TIMEOUT: return "504 Gateway Timeout";
    case HTTP_STATUS_HTTP_VERSION_NOT_SUPPORTED: return "505 HTTP Version Not Supported";
    case HTTP_STATUS_VARIANT_ALSO_NEGOTIATES: return "506 Variant Also Negotiates";
    case HTTP_STATUS_INSUFFICIENT_STORAGE: return "507 Insufficient Storage";
    case HTTP_STATUS_LOOP_DETECTED: return "508 Loop Detected";
    case HTTP_STATUS_BANDWIDTH_LIMIT_EXCEEDED: return "509 Bandwidth Limit Exceeded";
    case HTTP_STATUS_NOT_EXTENDED: return "510 Not Extended";
    case HTTP_STATUS_NETWORK_AUTHENTICATION_REQUIRED: return "511 Network Authentication Required";

    case HTTP_STATUS_WEB_SERVER_UNKNOWN_ERROR: return "520 Web Server Unknown Error";
    case HTTP_STATUS_WEB_SERVER_IS_DOWN: return "521 Web Server Is Down";
    case HTTP_STATUS_CONNECTION_TIMEOUT: return "522 Connection Timeout";
    case HTTP_STATUS_ORIGIN_IS_UNREACHABLE: return "523 Origin Is Unreachable";
    case HTTP_STATUS_TIMEOUT_OCCURED: return "524 Timeout Occurred";
    case HTTP_STATUS_SSL_HANDSHAKE_FAILED: return "525 SSL Handshake Failed";
    case HTTP_STATUS_INVALID_SSL_CERTIFICATE: return "526 Invalid SSL Certificate";
    case HTTP_STATUS_RAILGUN_ERROR: return "527 Railgun Error";
    case HTTP_STATUS_SITE_IS_OVERLOADED: return "529 Site is Overloaded";
    case HTTP_STATUS_SITE_IS_FROZEN: return "530 Site is Frozen";
    case HTTP_STATUS_IDENTITY_PROVIDER_AUTHENTICATION_ERROR: return "561 Identity Provider Authentication Error";
    case HTTP_STATUS_NETWORK_READ_TIMEOUT: return "598 Network Read Timeout";
    case HTTP_STATUS_NETWORK_CONNECT_TIMEOUT: return "599 Network Connect Timeout";

    default: return "UNKNOWN";
    }
}

Buffer assemble_http_message(const http_message_t *msg)
{
    assert(msg != NULL);

    // estimate space
    size_t estimate = 0;

    if (msg->status == 0) {
        estimate += 32 + msg->url_len; // Request line: METHOD SP URL SP HTTP/1.1 CRLF
    }
    else {
        estimate += 32; // response: HTTP/1.1 SP STATUS_TEXT CRLF
    }
    
    for (int i = 0; i < msg->num_headers; i++) {
        estimate += strlen(msg->headers[i].field) +
                    strlen(msg->headers[i].value) + 4;  // ": " + "\r\n"
    }
    estimate += 2;  // blank line after headers
    estimate += msg->body_len;

    // Allocate buffer
    char *buf = malloc(estimate + 1);
    if (!buf) return NULL;

    size_t off = 0;

    // Write request line
    if (msg->status == 0) {
        const char *method = llhttp_method_to_str((llhttp_method_t)msg->method);

        off += sprintf(buf + off, "%s %.*s HTTP/1.1\r\n",
                    method,
                    (int)msg->url_len,
                    msg->url);
    }
    else {
        const char *status_text = llhttp_status_to_string((llhttp_status_t)msg->status);
        off += sprintf(buf + off, "HTTP/1.1 %s\r\n", status_text);
    }
    

    // Write headers
    for (int i = 0; i < msg->num_headers; i++) {
        if (strcasecmp(msg->headers[i].field, HEADER_INJECTION_FIELD) == 0) {
            off += sprintf(buf + off, "%s:%s\r\n",
                       msg->headers[i].field,
                       msg->headers[i].value);
        }
        else {
            off += sprintf(buf + off, "%s: %s\r\n",
                       msg->headers[i].field,
                       msg->headers[i].value);
        }
    }

    // End header section
    memcpy(buf + off, "\r\n", 2);
    off += 2;

    // Write body
    if (msg->body && msg->body_len > 0) {
        memcpy(buf + off, msg->body, msg->body_len);
        off += msg->body_len;
    }

    Buffer buffer = Buffer_new(buf, off);
    free(buf);
    return buffer;
}

void inject_http_header(http_message_t *msg, char *field, char *value)
{
    assert(msg != NULL);
    assert(msg->num_headers < MAX_HEADERS);

    header_t *h = &msg->headers[msg->num_headers];

    // Field
    strncpy(h->field, field, MAX_HEADER_FIELD - 1);
    h->field[MAX_HEADER_FIELD - 1] = '\0';

    // Value
    strncpy(h->value, value, MAX_HEADER_VALUE - 1);
    h->value[MAX_HEADER_VALUE - 1] = '\0';

    msg->num_headers++;
}

bool Http_Msg_has(http_message_t *msg, char *field, char *value)
{
    assert(msg != NULL);
    assert(field != NULL);
    assert(value != NULL);

    for (int i = 0; i < msg->num_headers; i++) {
        if (strcasecmp(msg->headers[i].field, field) == 0) {
            return (strstr(msg->headers[i].value, value) != NULL);
        }
    }

    return false;
}

/* caller responsible for freeing hostname */
char *get_host_and_port(const http_message_t *msg, int *port)
{
    assert(msg != NULL);

    char *host_value = NULL;

    if ((llhttp_method_t)msg->method == HTTP_GET) {
        for (int i = 0; i < msg->num_headers; i++) {
            if (strcasecmp(msg->headers[i].field, "Host") == 0) {
                host_value = strdup(msg->headers[i].value);
                break;
            }
        }
    }
    else if ((llhttp_method_t)msg->method == HTTP_CONNECT) {
        const char *scheme_end = strstr(msg->url, "://");
        if (host_value == NULL) {
            // No scheme found, assume it's just a hostname/IP
            host_value = strdup(msg->url);
        } else {
            host_value = strdup(scheme_end + 3); // Move past "://"
            // host_value += 3; 
        }

        char *authority_end = NULL;
        authority_end = strchr(host_value, '/');
        if (authority_end)
            *authority_end = '\0';
    }

    if (!host_value) {
        printf("No host header\n");
        return NULL; // No Host header found
    }

    const char *host_start = host_value;
    const char *host_end   = NULL;
    const char *port_sep   = NULL;
    
    host_end = strchr(host_value, ':');
    if (host_end) // port delimiter found
        port_sep = host_end + 1;
    else
        host_end = host_value + strlen(host_value);

    if (port_sep && *port_sep) {
        int try_port = atoi(port_sep);
        if (try_port > 0) {
            *port = try_port;
        }
    }

    size_t name_len = (size_t)(host_end - host_start);
    char *hostname = malloc(name_len + 1);
    if (!hostname) return NULL;

    memcpy(hostname, host_start, name_len);
    hostname[name_len] = '\0';

    free(host_value);

    return hostname;
}

/* 
caller responsible for freeing the copy
*/
http_message_t* Http_Msg_deep_copy(const http_message_t* src) {
    assert(src != NULL);

    // Allocate memory for the new message
    http_message_t* copy = malloc(sizeof(http_message_t));
    assert(copy != NULL);

    // Copy simple fields
    copy->method = src->method;
    copy->status = src->status;
    copy->url_len = src->url_len;
    memcpy(copy->url, src->url, src->url_len);
    copy->url[src->url_len] = '\0';

    // Copy headers
    copy->num_headers = src->num_headers;
    for (int i = 0; i < src->num_headers; i++) {
        strncpy(copy->headers[i].field, src->headers[i].field, MAX_HEADER_FIELD);
        strncpy(copy->headers[i].value, src->headers[i].value, MAX_HEADER_VALUE);
    }

    // Allocate and copy body
    copy->body_len = src->body_len;
    copy->body_cap = src->body_len; // minimal capacity = actual length
    if (src->body_len > 0) {
        copy->body = malloc(src->body_len);
        if (!copy->body) {
            free(copy);
            return NULL;
        }
        memcpy(copy->body, src->body, src->body_len);
    } else {
        copy->body = NULL;
    }

    // Buffer buf = assemble_http_message(copy);
    // printf("copy of message:\n%s\n", Buffer_content(buf));

    return copy;
}