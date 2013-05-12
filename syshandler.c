#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/event.h>
#include <sys/time.h>
#include <pthread.h>

#include "include/common.h"
#include "include/net.h"
#include "include/syscons.h"
#include "include/sysproto.h"

#define ETX 03

Errors ErrCodes[] = {
	{ 0, "Complate", }, 
	{ 1, "Authorized failed", },
	{ 2, "Data not valid", },
};

static struct kevent *ke_vec = NULL;
static unsigned ke_vec_alloc = 0;
static unsigned ke_vec_used = 0;
static char const protoname[] = "tcp";
static int client_end =0;

static void
ke_change (int const ident,
	   int const filter,
	   int const flags,
	   void *const udata)
{
  enum { initial_alloc = 64 };
  struct kevent *kep;

  if (!ke_vec_alloc)
    {
      ke_vec_alloc = initial_alloc;
      ke_vec = (struct kevent *) xmalloc(ke_vec_alloc * sizeof (struct kevent), "sys_kevent");
    }
  else if (ke_vec_used == ke_vec_alloc)
    {
      ke_vec_alloc <<= 1;
      ke_vec =
	(struct kevent *) xrealloc (ke_vec,
				    ke_vec_alloc * sizeof (struct kevent));
    }

  kep = &ke_vec[ke_vec_used++];

  kep->ident = ident;
  kep->filter = filter;
  kep->flags = flags;
  kep->fflags = 0;
  kep->data = 0;
  kep->udata = udata;
}

static void
do_write (struct kevent const *const kep)
{
  int n, sizeOfBuf;
  ecb *const ecbp = (ecb *) kep->udata;
  char *nstr = "\r\n";
  char *buffer;


  switch(ecbp->error)
  {
	  case 0: sizeOfBuf = strlen(ErrCodes[0].value)+sizeof(int);
		  buffer = xmalloc(sizeOfBuf, "sys_outBuffer");
		  memcpy(buffer, &ErrCodes[0].id, sizeof(int));
		  memcpy(buffer+sizeof(int), ErrCodes[0].value, strlen(ErrCodes[0].value));
		  break;
	  case 1: sizeOfBuf = strlen(ErrCodes[1].value)+sizeof(int);
		  buffer = xmalloc(sizeOfBuf, "sys_outBuffer");
		  memcpy(buffer, &ErrCodes[1].id, sizeof(int));
		  memcpy(buffer+sizeof(int), ErrCodes[1].value, strlen(ErrCodes[1].value));
		  break;
	  case 2: sizeOfBuf = strlen(ErrCodes[2].value)+sizeof(int);
		  buffer = xmalloc(sizeOfBuf, "sys_outBuffer");
		  memcpy(buffer, &ErrCodes[2].id, sizeof(int));
		  memcpy(buffer+sizeof(int), ErrCodes[2].value, strlen(ErrCodes[1].value));
		  break;
	  default:
		  break;
  };
//  n = write (kep->ident, ecbp->buf, ecbp->bufsiz);
  n = write (kep->ident, buffer, sizeOfBuf);
  xfree(buffer);


//  xfree (ecbp->buf);  /* Free this buffer, no matter what.  */
  if (n == -1)
    {
      ERROR_ARGS("Error writing socket: %s", strerror (errno));
      close (kep->ident);
      xfree (ecbp->client);
      xfree (kep->udata);
    }

//  if (ecbp->buf != NULL && ecbp->buf[0] == EOF)
//	write (kep->ident, (void *)nstr, 2);	  
  ke_change (kep->ident, EVFILT_WRITE, EV_DISABLE, kep->udata);
  ke_change (kep->ident, EVFILT_READ, EV_ENABLE, kep->udata);
}

static void
do_read (struct kevent const *const kep)
{
  enum { bufsize = 10024 };
  auto char buf[bufsize];
  auto char encbuf[bufsize];
  int n;
  int ret;
  ecb *const ecbp = (ecb *) kep->udata;

  bzero(buf, bufsize);
  bzero(encbuf, bufsize);
  DPRINT_ARGS ("client %s", inet_ntoa(ecbp->client->ip));

  if ((n = read (kep->ident, buf, bufsize)) == -1)
    {
      DPRINT_ARGS("Error reading socket: %s", strerror (errno));
      close (kep->ident);
      xfree (ecbp->client);
      xfree (kep->udata);
    }
  else if (n == 0)
    {
      DPRINT_ARGS ("EOF reading socket for client %s", inet_ntoa(ecbp->client->ip));
      close (kep->ident);
      xfree (ecbp->client);
      xfree (kep->udata);
      client_end = 1;
    }

  DPRINT_ARGS("GET %d bytes", n);
  encrypt_decrypt(encbuf, buf, n);

  parse_incomming(encbuf, ecbp->client->ip, n, &ecbp->client->reqcount, kep);
/*  if(ret>0)
  {
	  DPRINT_ARGS("Result parse: %d", ret);
	  ecbp->buf = (char *) xmalloc (ret, "sys_in_ret");
	  ecbp->bufsiz = ret;
	  //memcpy (ecbp->buf, tempbuf, ret);
  }
  else if (ret == 0)
  {
	  ecbp->buf = (char *) xmalloc (n, "sys_buf_size");
	  ecbp->bufsiz = n;
	  memcpy (ecbp->buf, buf, n);
  }
  else if (ret == -1)
  {
      close (kep->ident);
      xfree (ecbp->client);
      xfree (kep->udata);
      client_end = 1;
  };*/

  ke_change (kep->ident, EVFILT_READ, EV_DISABLE, kep->udata);
  ke_change (kep->ident, EVFILT_WRITE, EV_ENABLE, kep->udata);
}

static void
do_accept (struct kevent const *const kep)
{
  auto sockaddr_in sin;
  auto socklen_t sinsiz;
  int s, n;
  ecb *ecbp;
  client_info *cinfo;

  sinsiz = sizeof(sockaddr_in);
  if ((s = accept (kep->ident, (struct sockaddr *)&sin, &sinsiz)) == -1)
    FATAL_ARGS("Error in accept(): %s", strerror (errno));
  DPRINT_ARGS("ACCEPT: %s", inet_ntoa(sin.sin_addr));

  ecbp = (ecb *) xmalloc (sizeof (ecb), "sys_ecb");
  cinfo = (client_info *) xmalloc (sizeof (client_info), "sys_clientinfo");
  cinfo->ip = sin.sin_addr;
  cinfo->reqcount = 0;
  ecbp->client = cinfo;
  ecbp->do_read = do_read;
  ecbp->do_write = do_write;
//  ecbp->buf = NULL;
//  ecbp->bufsiz = 0;

  ke_change (s, EVFILT_WRITE, EV_ADD | EV_ENABLE, ecbp);
  ke_change (s, EVFILT_READ, EV_ADD | EV_DISABLE, ecbp);
}

static void event_loop (int const kq)
    __attribute__ ((__noreturn__));

static void
event_loop (int const kq)
{
  for (;;)
    {
      int n,i;
      struct kevent const *kep;

      n = kevent (kq, ke_vec, ke_vec_used, ke_vec, ke_vec_alloc, NULL);
      ke_vec_used = 0;  /* Already processed all changes.  */

      if (n == -1)
        FATAL_ARGS("Error in kevent(): %s", strerror (errno));
      if (n == 0)
        FATAL("No events received!");

      for (i = 0; i < n; ++i)
        {
	    kep = &ke_vec[i];   	
          ecb const *const ecbp = (ecb *) kep->udata;
    
	  if (kep->flags & EV_ERROR || kep->flags & EV_EOF)
	  {
		  ERROR_ARGS("EV_ERROR: %s\n", strerror(kep->data));
		  close(kep->ident);
		  continue;
	  };
	  if (kep->flags & EV_DELETE)
	  {
		  close(kep->ident);
		  continue;
	  };
	  if (ecbp->do_read==0)
		  continue;
	  if (kep->filter == EVFILT_READ)
	    (*ecbp->do_read) (kep);
	  else if (kep->filter == EVFILT_WRITE)
	    (*ecbp->do_write) (kep);
        }

    }
};

void *
start_syshandle(void *arg)
{
  auto in_addr listen_addr;
  int optch;
  auto int one = 1;
  int portno = 0;
  int option_errors = 0;
  int server_sock;
  auto sockaddr_in sin;
  servent *servp;
  auto ecb listen_ecb;
  int kq;


  LIST_INIT(&ServersCtl);
  listen_addr.s_addr = inet_addr(configVar[3].value);  /* Default.  */

  if ((server_sock = socket (PF_INET, SOCK_STREAM, 0)) == -1)
    FATAL_ARGS("Error creating socket: %s", strerror (errno));


  if (setsockopt(server_sock, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one) == -1)
    FATAL_ARGS("Error setting SO_REUSEADDR for socket: %s", strerror (errno));

  memset (&sin, 0, sizeof sin);
  sin.sin_family = AF_INET;
  sin.sin_addr = listen_addr;
  sin.sin_port = htons (atoi(configVar[4].value));  


  if (bind (server_sock, (const struct sockaddr *)&sin, sizeof sin) == -1)
    FATAL_ARGS("Error binding socket: %s", strerror (errno));


  if (listen (server_sock, 20) == -1)
    FATAL_ARGS("Error listening to socket: %s", strerror (errno));

//  NOTICE("Test sys");
  if ((kq = kqueue ()) == -1)
    FATAL_ARGS("Error creating kqueue: %s", strerror (errno));

  listen_ecb.do_read = do_accept;
  listen_ecb.do_write = NULL;
  listen_ecb.buf = NULL;
  listen_ecb.buf = 0;

  ke_change (server_sock, EVFILT_READ, EV_ADD | EV_ENABLE, &listen_ecb);
  ke_change (server_sock, EVFILT_WRITE, EV_ADD | EV_DISABLE, &listen_ecb);

  event_loop (kq);
}
