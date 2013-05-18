#pragma once

//#define NUMNETTHREADS	2

/* Event Control Block (ecb) */
typedef void (action) (register struct kevent const *const kep);

typedef struct in_addr in_addr;

typedef struct {
    in_addr	ip;
    int		port;
    int		reqcount;
} client_info;

/* struct for HTTP query */
typedef struct {
    char path[MAXPATHLEN];
    char type[10];
    char version[10];
    int  code;
} http_request;

typedef struct {
    void *buffer;	
    void *offset;
    long long size;
    unsigned int gotsize;
} bufcontrol;

/* Control event struct for system thread */
typedef struct {
    action	*do_read;
    action	*do_write;
    char	*buf;
    unsigned	bufsiz;
    client_info *client;
    char	*arg;
    int		error;
    bufcontrol  *bctrl;
} ecb;

/* Control event struct for http thread */
typedef struct {
    action	*do_http_read;
    action	*do_http_write;
    char	*buf;
    unsigned int bufsiz;
    client_info *client;
    http_request *req;
    int		end_connection;
} ecbhttp;

/* admin login control */
LIST_HEAD(adminAccess_head, adminAccess) adminAccessCtl;
struct adminAccess_head *adminAccess_headp;
struct adminAccess
{
    in_addr ip;
    char login[50];
    int ident;
    LIST_ENTRY(adminAccess) adminAccess_list;
};

pthread_mutex_t	connectMutex;
pthread_mutex_t	memMutex;

typedef struct sockaddr_in sockaddr_in;
typedef struct servent servent;
typedef struct timespec timespec;

static void do_write (register struct kevent const *const kep);
static void do_read (register struct kevent const *const kep);
static void do_http_write (register struct kevent *kep);
static void do_http_read (register struct kevent *kep);
static void ke_change (register int const ident, register int const filter, register int const flags, register void *const udata);
void *start_syshandle(void *arg);
void *start_httphandle(void *arg);
void httprequest(register struct kevent *kep);
void httpresponse(register struct kevent *kep);
static void client_free(register struct kevent  *kephttp);
