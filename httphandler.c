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

#include <sys/stat.h>
#include <fcntl.h>
#include <sys/uio.h>

#include "include/common.h"
#include "include/net.h"
#include "include/http_parser.h"
#include "include/http_pages.h"
int kqg;
static struct kevent *ke_vec = NULL;
static unsigned ke_vec_alloc = 0;
unsigned int ke_vec_used = 0;
static char const protoname[] = "tcp";
static int client_end =0;
static int reading_pages = 0;
static int initpage_cnt = 0;

static void
ke_change (int const ident,
	   int const filter,
	   int const flags,
	   void *const udata)
{
  enum { initial_alloc = 100500 };
  struct kevent *kephttp;

  if (!ke_vec_alloc)
    {
      ke_vec_alloc = initial_alloc;
      ke_vec = (struct kevent *) xmalloc(ke_vec_alloc * sizeof (struct kevent), "kevent");
    }
  else if (ke_vec_used == ke_vec_alloc)
    {
      ke_vec_alloc <<= 1;
      ke_vec =
	(struct kevent *) xrealloc (ke_vec,
				    ke_vec_alloc * sizeof (struct kevent));
    }
  kephttp = &ke_vec[ke_vec_used++];

  kephttp->ident = ident;
  kephttp->filter = filter;
  kephttp->flags = flags;
  kephttp->fflags = 0;
  kephttp->data = 0;
  kephttp->udata = udata;

//  register ecbhttp const *const ecbp = (ecbhttp *) udata;
//  DPRINT_ARGS("KEP_HTTP->UDATA->REQ: %p", ecbp->req);

//  DPRINT_ARGS("KE_CHANGE http_read=%p http_write:=%p", ecbp->do_http_read, ecbp->do_http_write);
}

static void
do_http_write (struct kevent *kephttp)
{
  int n, code, retcode, offset, size;
  ecbhttp *ecbp = (ecbhttp *) kephttp->udata;
  char buffer[20000];
  FILE * fd = NULL;
  char *staticfile, *asize;
  size_t staticsize;
  struct stat stat_buf;
  off_t foffset = 0;

//  buffer = xmalloc(50000, "buf1");

  bzero(buffer, 20000);
  if (!configVar[9].isset && atoi(configVar[9].value) == 0)
    if (init_pages())
	FATAL("Init pages failed");  

  DPRINT_ARGS("KEP_HTTP->UDATA->REQ: %p", ecbp->req);
	  
  if(kephttp!=0)
    retcode = get_response(buffer, kephttp, reading_pages);
  else
    retcode = 404;	  
  switch(retcode)
  {
	case 200:
		n = write(kephttp->ident, buffer, strlen(buffer));
		break;
	case 202:
		if ((fd = fopen(buffer, "r"))==NULL)
		{
		    NOTICE_ARGS("%s GET %s CODE 404", inet_ntoa(ecbp->client->ip), buffer);
		    bzero(buffer, strlen(buffer));
		    sprintf(buffer, "%s%zd\n\n%s", HEAD404, strlen(page404), page404);
		    n = write(kephttp->ident, buffer, strlen(buffer));
		    if (n == -1)
		    {
			ERROR_ARGS("Error writing socket: %s", strerror (errno));
			client_free(kephttp);
			return;
		    };
		    break;
		};
		DPRINT_ARGS("OPEN: %s", buffer);
		fseek(fd, 0, SEEK_END);
		size = ftell(fd);
		fseek(fd, 0, SEEK_SET);

		staticfile = xmalloc(size, "statfile");
		staticsize = fread(staticfile, 1, size, fd);
		asize = xmalloc(strlen(HEAD202)+strlen(staticfile), "tempst");
		//bzero(asize, strlen(HEAD202)+strlen(staticfile)+40);
		sprintf(asize, "%s%zd\n\n%s", HEAD202, strlen(staticfile), staticfile);
		n = write(kephttp->ident, asize, strlen(asize));
		xfree(asize);
		xfree(staticfile);
		if (n == -1)
		{
		    //ERROR_ARGS("Error writing socket: %s", strerror (errno));
		    //DPRINT_ARGS("client %s session: %d Error writing socket: %s", inet_ntoa(ecbp->client->ip), ecbp->client->sessId, strerror (errno));
		    client_free(kephttp);
		    return;
		}

		fclose(fd);
		break;
	case 404:
		n = write(kephttp->ident, buffer, strlen(buffer));
		if (n == -1)
		{
		    ERROR_ARGS("Error writing socket: %s", strerror (errno));
		    client_free(kephttp);
		    return;
		};
		break;
	default:
///		xfree(buffer);
		break;
  };
  DPRINT_ARGS("REQUEST: %s", ecbp->req);
  //xfree (ecbp->buf);  /* Free this buffer, no matter what.  */
  if (reading_pages)
    free_pages_buf();
  DPRINT_ARGS("REQ=%s", ecbp->req->path);
  if (ecbp->req->path)
  {
    DPRINT("FREE REQ;");	  
    //xfree(ecbp->req);
 }

  ke_change (kephttp->ident, EVFILT_WRITE, EV_DISABLE, kephttp->udata);
  ke_change (kephttp->ident, EVFILT_READ, EV_ENABLE, kephttp->udata);
}

static void
do_http_read (struct kevent *kephttp)
{
  enum { bufsize = 512 };
  auto char buf[bufsize];
  int n, result;
  ecbhttp *ecbp = (ecbhttp *) kephttp->udata;
  memset(buf, 0, bufsize);

  if ((n = read (kephttp->ident, buf, bufsize)) == -1)
    {
      DPRINT_ARGS("client %s Error reading socket: %s", inet_ntoa(ecbp->client->ip), strerror (errno));
      client_free(kephttp);
      //return;
    }
  else if (n == 0)
    {
      DPRINT_ARGS ("EOF reading socket for client %s", inet_ntoa(ecbp->client->ip));
      client_free(kephttp);
      //return;
    }
  result = parse_http_request(kephttp, buf);
  if (result == -1 )
  {
      DPRINT_ARGS("request from client %s not correct.", inet_ntoa(ecbp->client->ip));		  
      client_free(kephttp);
     // return;
  }
  else 
  {
    xfree(ecbp->buf);	  
    DPRINT_ARGS("READ FROM CLIENT %d bytes.", n);		  
    ecbp->buf = (char *) xmalloc (n, "bufsize");
    ecbp->bufsiz = n;
    memcpy (ecbp->buf, buf, n);
  };

  DPRINT_ARGS("KEP_HTTP->UDATA->REQ: %p", ecbp->req);
  ke_change (kephttp->ident, EVFILT_READ, EV_DISABLE, kephttp->udata);
  ke_change (kephttp->ident, EVFILT_WRITE, EV_ENABLE, kephttp->udata);
}

static void
do_http_accept (struct kevent * kephttp)
{
  auto sockaddr_in sin;
  auto socklen_t sinsiz;
  int s;
  auto ecbhttp *ecbp;
  auto client_info *cinfo;
  struct adminAccess *adminEntry; 

  adminEntry = NULL;

  sinsiz = sizeof(sockaddr_in);

  if ((s = accept (kephttp->ident, (struct sockaddr *)&sin, &sinsiz)) == -1)
  {
    ERROR_ARGS("Error in accept(): %s", strerror (errno));
  }

  NOTICE_ARGS("Client %s accepted", inet_ntoa(sin.sin_addr));
  if (sinsiz != sizeof(sin))
	  DPRINT("Accepted not valid!");  

  //adminEntry = malloc(sizeof(struct adminAccess));
  adminEntry = xmalloc(sizeof(struct adminAccess), "adminEntry");
//  bzero(adminEntry, sizeof(struct adminAccess));
  adminEntry->ip = sin.sin_addr;
  adminEntry->ident = kephttp->ident;


  strcpy(adminEntry->login, "admin");
  LIST_INSERT_HEAD(&adminAccessCtl, adminEntry, adminAccess_list);
  DPRINT("INSERT TO ADMIN!!!");
  ecbp = (ecbhttp *) xmalloc (sizeof (ecbhttp), "ecbcontrol");
  cinfo = (client_info *) xmalloc (sizeof (client_info), "clientinfo");
  cinfo->ip = sin.sin_addr;
  ecbp->client = cinfo;
  ecbp->do_http_read = (action *)do_http_read;
  ecbp->do_http_write = (action *)do_http_write;
  ecbp->buf = NULL;
  ecbp->req = NULL;
  ecbp->bufsiz = 0;
  DPRINT_ARGS("START %s http_read=%x http_write:=%x", inet_ntoa(adminEntry->ip), ecbp->do_http_read, ecbp->do_http_write);
  /* put in Admin control access list */


  ke_change (s, EVFILT_READ, EV_ADD | EV_ENABLE, ecbp);
  ke_change (s, EVFILT_WRITE, EV_ADD | EV_DISABLE, ecbp);
};

static void event_loop (int const kq)
    __attribute__ ((__noreturn__));

static void
event_loop (int const kq)
{

	kqg = kq;
	for (;;)
	{
		int n, i;
//		register struct kevent const *kephttp;
		struct kevent *kephttp;

		n = kevent (kq, ke_vec, ke_vec_used, ke_vec, ke_vec_alloc, NULL);
		ke_vec_used = 0;  /* Already processed all changes.  */

		if (n == -1)
			FATAL_ARGS("Error in kevent(): %s", strerror (errno));
		if (n == 0)
			FATAL("No events received!");

		
		for(i = 0; i < n; ++i)
//		for (kephttp = ke_vec; kephttp < &ke_vec[n]; kephttp++)
		{

			kephttp = &ke_vec[i];


			ecbhttp *ecbp = (ecbhttp *) kephttp->udata;

			//ecbp->do_http_read = do_http_read;
			//ecbp->do_http_write = do_http_write;

	//		if (!kephttp->ident)
	//		{
		//		do_http_accept();
	//			close(kephttp->ident);
	//			client_end = 0;
	//			continue;
	//		}
			//else

			//{
	//		    if (ecbp->client)
	//		    DPRINT_ARGS("START KQ %d - %d, %s", kq, ecbp->end_connection, inet_ntoa(ecbp->client->ip));
	//		    DPRINT_ARGS("LOOP%d: %p %p TYPES: %d %d %d", i, ecbp->do_http_read, ecbp->do_http_write, EV_ERROR, EVFILT_READ, EVFILT_READ);	


		    if (kephttp->flags & EV_ERROR || kephttp->flags & EV_EOF)
			    {
				ERROR_ARGS("EV_ERROR: %s\n", strerror(kephttp->data));
				free(ecbp->client);
				ecbp->client=NULL;
				free(ecbp->req);
				ecbp->req = NULL;
				free(ecbp->buf);
				ecbp->buf = NULL;
			//	if (kephttp->ident)
				close(kephttp->ident);
				//free(ecbp);
				//ecbp = NULL;

				break;
			    };
			    if (kephttp->flags & EV_DELETE)
			    {
				//close(kephttp->ident);
				//free(ecbp->client);
				continue;
			    };
			    if (ecbp->do_http_read==0)
				    continue;
			    if (kephttp->filter == EVFILT_READ)
				(*ecbp->do_http_read) (kephttp);
			    else if (kephttp->filter == EVFILT_WRITE)
				    (*ecbp->do_http_write) (kephttp);
		}

	}
};

void *
start_httphandle(void *arg)
{
  auto in_addr listen_addr;
  int optch;
  auto int one = 1;
  int portno = 0;
  int option_errors = 0;
  int server_sock = 0;
  auto sockaddr_in sin;
  servent *servp;
  auto ecbhttp listen_ecb;
  int kq;
  int tmout = 10;

  if (configVar[9].isset && atoi(configVar[9].value) == 1)
  {
    if (init_pages())
	FATAL("Init pages failed");  
  }
  else
	reading_pages = 1;  
  
  listen_addr.s_addr = inet_addr(configVar[1].value);  /* Default.  */

  if ((server_sock = socket (PF_INET, SOCK_STREAM, 0)) == -1)
    FATAL_ARGS("Error creating socket: %s", strerror (errno));

  if (setsockopt(server_sock, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)) == -1)
    FATAL_ARGS("Error setting SO_REUSEADDR for socket: %s", strerror (errno));

  memset(&sin, 0, sizeof(sockaddr_in));
  sin.sin_family = AF_INET;
  sin.sin_addr = listen_addr;
  sin.sin_port = htons (atoi(configVar[2].value));  

  if (bind (server_sock, (const struct sockaddr *)&sin, sizeof(sockaddr_in)) == -1)
    FATAL_ARGS("Error binding socket: %s", strerror (errno));

  if (listen (server_sock, 20) == -1)
    FATAL_ARGS("Error listening to socket: %s", strerror (errno));

  if ((kq = kqueue ()) == -1)
    FATAL_ARGS("Error creating kqueue: %s", strerror (errno));

  listen_ecb.do_http_read = (action *)do_http_accept;
  listen_ecb.do_http_write = NULL;
  listen_ecb.buf = NULL;
  listen_ecb.req = NULL;
  listen_ecb.buf = 0;

  //ke_change (server_sock, EVFILT_READ, EV_ADD | EV_ENABLE, &listen_ecb);
  ke_change (server_sock, EVFILT_READ, EV_ADD | EV_ENABLE, &listen_ecb);
  ke_change (server_sock, EVFILT_WRITE, EV_ADD | EV_DISABLE, &listen_ecb);
//  EV_SET(ke_vec, server_sock, EVFILT_READ, EV_ADD, 0, 0, NULL);
//  kevent(kq, ke_vec, 1, 0, 0, NULL);
  event_loop (kq);
}

int
init_pages(void)
{
	FILE *fd;
	int size;
	char *page=NULL;
	char path[MAXPATHLEN];

	/* init page 404 */
	bzero(path, MAXPATHLEN);
	strcpy(path, configVar[8].value);
	page = strcat(path, PAGE404);

	if ((fd = fopen(page, "r"))==NULL)
		FATAL_ARGS("fopen %s: %s", page, strerror(errno));

	fseek(fd, 0, SEEK_END);
	size = ftell(fd);
	fseek(fd, 0, SEEK_SET);

	page404 = xmalloc(size+1, "page404");
	fread(page404, 1, size, fd);

	fclose(fd);

	/* init page /admin/ */
	bzero(path, strlen(path));
	strcpy(path, configVar[8].value);
	page = strcat(path, PAGEADMIN);
	if ((fd = fopen(page, "r"))==NULL)
		FATAL_ARGS("fopen %s: %s", page, strerror(errno));

	fseek(fd, 0, SEEK_END);
	size = ftell(fd);
	fseek(fd, 0, SEEK_SET);

	pageAdmin = xmalloc(size, "pageAdmin");
	fread(pageAdmin, 1, size, fd);

	fclose(fd);
	initpage_cnt++;
	return 0;
};

void
free_pages_buf(void)
{
	xfree(page404);
	xfree(pageAdmin);
};

static void 
//client_free(register struct kevent const* const kephttp)
client_free(struct kevent * kephttp)
{
    ecbhttp *ecbp = (ecbhttp *) kephttp->udata;
    struct adminAccess *adminAccess_entry;
    int found=0;

    LIST_FOREACH(adminAccess_entry, &adminAccessCtl, adminAccess_list)
    {
	if (adminAccess_entry->ident == kephttp->ident)
	{

	    LIST_REMOVE(adminAccess_entry, adminAccess_list);
	    xfree(adminAccess_entry);
	    DPRINT_ARGS("REMOVE client %s from list", inet_ntoa(adminAccess_entry->ip));   
	    break;
	};
      };
      //xfree(ecbp->req);


 //     if(kevent(kq, kephttp, 1,0,0,NULL) < 0) perror("kevent()");
    //  close(kephttp->ident);
      //xfree (ecbp->client);
      //xfree(ecbp->req);
      //xfree (kephttp->udata);
      client_end=1;
//  ke_change (kephttp->ident, EVFILT_READ, EV_DELETE, kephttp->udata);
//  ke_change (kephttp->ident, EVFILT_WRITE, EV_DELETE, kephttp->udata);
};
