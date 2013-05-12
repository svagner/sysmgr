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

pthread_t thread[NUMNETTHREADS];
void
start_service (void)
{

  int threadid[NUMNETTHREADS], i;
  int result;
  void *a;
  a = NULL;

  threadid[0] = 1;
  threadid[1] = 2;

 // if (pthread_mutex_init(&connectMutex, NULL))
//	  FATAL("Set mutex error");

  result = pthread_create(&thread[0], NULL, start_httphandle, &threadid[0]);
  if (result)
    FATAL("Error creating http thread. Exiting...");	  
  result = pthread_create(&thread[1], NULL, start_syshandle, &threadid[1]);
  if (result)
    FATAL("Error creating sys thread. Exiting...");	  
  for (i=0; i<NUMNETTHREADS; i++)
    if(pthread_join(thread[i], NULL))
	    FATAL_ARGS("Error joined in the thread %d. Exiting...", threadid[i]);
//  pthread_join(thread[0], NULL);
//  start_httphandle(a);
}
