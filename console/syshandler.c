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

#define ETX 03

static struct kevent *ke_vec = NULL;
static unsigned ke_vec_alloc = 0;
static unsigned ke_vec_used = 0;
static char const protoname[] = "tcp";
static int client_end =0;

static void
ke_change (register int const ident,
	   register int const filter,
	   register int const flags,
	   register void *const udata)
{
  enum { initial_alloc = 64 };
  register struct kevent *kep;

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
do_write (register struct kevent const *const kep)
{
  register int n;
  register ecb *const ecbp = (ecb *) kep->udata;
  char *nstr = "\r\n";


  if (ecbp->client->reqcount==0)
  {
    n = write (kep->ident, ACCEPTHELLO, sizeof(ACCEPTHELLO));
    ecbp->client->reqcount++;
    return;
  };


  n = write (kep->ident, ecbp->buf, ecbp->bufsiz);


  xfree (ecbp->buf);  /* Free this buffer, no matter what.  */
  if (n == -1)
    {
      ERROR_ARGS("Error writing socket: %s", strerror (errno));
      close (kep->ident);
      xfree (ecbp->client);
      xfree (kep->udata);
    }

  if (ecbp->buf != NULL && ecbp->buf[0] == EOF)
	write (kep->ident, (void *)nstr, 2);	  
  n = write (kep->ident, CONSHELLO, sizeof(CONSHELLO));
  ke_change (kep->ident, EVFILT_WRITE, EV_DISABLE, kep->udata);
  ke_change (kep->ident, EVFILT_READ, EV_ENABLE, kep->udata);
}

static void
do_read (register struct kevent const *const kep)
{
  enum { bufsize = 1024 };
  auto char buf[bufsize], tempbuf[bufsize];
  register int n;
  register int ret;
  register ecb *const ecbp = (ecb *) kep->udata;

  bzero(buf, bufsize);

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

  ret=parse_incomming(buf, tempbuf, n, &ecbp->client->reqcount);
  if(ret>0)
  {
	  DPRINT_ARGS("Result parse: %d", ret);
	  ecbp->buf = (char *) xmalloc (ret, "sys_in_ret");
	  ecbp->bufsiz = ret;
	  memcpy (ecbp->buf, tempbuf, ret);
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
  };

  ke_change (kep->ident, EVFILT_READ, EV_DISABLE, kep->udata);
  ke_change (kep->ident, EVFILT_WRITE, EV_ENABLE, kep->udata);
}

static void
do_accept (register struct kevent const *const kep)
{
  auto sockaddr_in sin;
  auto socklen_t sinsiz;
  register int s, n;
  register ecb *ecbp;
  register client_info *cinfo;

  if ((s = accept (kep->ident, (struct sockaddr *)&sin, &sinsiz)) == -1)
    FATAL_ARGS("Error in accept(): %s", strerror (errno));

  ecbp = (ecb *) xmalloc (sizeof (ecb), "sys_ecb");
  pthread_mutex_lock(&connectMutex);
  cinfo = (client_info *) xmalloc (sizeof (client_info), "sys_clientinfo");
  cinfo->ip = sin.sin_addr;
  cinfo->reqcount = 0;
  ecbp->client = cinfo;
  pthread_mutex_lock(&connectMutex);
  ecbp->do_read = do_read;
  ecbp->do_write = do_write;
  ecbp->buf = NULL;
  ecbp->bufsiz = 0;

  ke_change (s, EVFILT_WRITE, EV_ADD | EV_ENABLE, ecbp);
  ke_change (s, EVFILT_READ, EV_ADD | EV_DISABLE, ecbp);
}

static void event_loop (register int const kq)
    __attribute__ ((__noreturn__));

static void
event_loop (register int const kq)
{
  for (;;)
    {
      register int n,i;
      register struct kevent const *kep;

      n = kevent (kq, ke_vec, ke_vec_used, ke_vec, ke_vec_alloc, NULL);
      ke_vec_used = 0;  /* Already processed all changes.  */

      if (n == -1)
        FATAL_ARGS("Error in kevent(): %s", strerror (errno));
      if (n == 0)
        FATAL("No events received!");

      for (i = 0; i < n; ++i)
        {
	    kep = &ke_vec[i];   	
          register ecb const *const ecbp = (ecb *) kep->udata;
    
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
  register int optch;
  auto int one = 1;
  register int portno = 0;
  register int option_errors = 0;
  register int server_sock;
  auto sockaddr_in sin;
  register servent *servp;
  auto ecb listen_ecb;
  register int kq;


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

  event_loop (kq);
}
