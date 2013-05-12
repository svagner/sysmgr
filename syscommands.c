//#include <stdarg.h>
//#include <stdio.h>
//#include <string.h>
//#include <netinet/in.h>

#include <stdio.h>
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
#include <sys/queue.h>

#include "include/syscmds.h"
#include "include/common.h"
#include "include/sysproto.h"
#include "include/net.h"

#define CMDNFOUND "Command not found. Call [help] please.\r\n"

int 
help_cmd (char *arg, char *outbuf) {
    char help[] = "show help...";
    char *delim = " ";
    char *buf;
    char final[1024];
    int i;

    if (arg==NULL)	
    {	    
	memcpy(outbuf, help, strlen(help));
	return strlen(help);
    };
    buf = strtok(arg, delim);
    if (strcmp(buf, "help"))
    {
	    memcpy(outbuf, CMDNFOUND, strlen(CMDNFOUND));
	    return strlen(CMDNFOUND);
    }
    while(buf!=NULL)
    {
	buf = strtok(NULL, delim);
	if (buf==NULL)
	{
	    sprintf(final, "Usage commands:\n");	
	    for	(i=0; i<sizeof(commands)/sizeof(*commands); i++)
	    {	    
		strcat(final, "\t\t");
		strcat(final, commands[i].name);    
		strcat(final, "\n\0");
	    };
	    memcpy(outbuf, final, strlen(final));
	    return strlen(final);
	}
	else
	    memcpy(outbuf, "\r", 1);	
	    return 1;
	    break;
    };
    memcpy(outbuf, arg, strlen(arg));
    return strlen(arg);
}

int
show_cmd (char *arg, char *outbuf) {
    char help[] = "please, input 'help show'";
    if (arg==NULL)	
    {	    
	memcpy(outbuf, help, strlen(help));
	return strlen(help);
    };
    
    memcpy(outbuf, arg, strlen(arg));
    return strlen(arg);
};

void
parse_incomming(char *buf, struct in_addr client, int bufsize, int *retcount, struct kevent const *const kep)
{
	char user[MAXUSERLEN];
	char passwd[MAXPASSLEN];
	int foundServer=0;
	SInfo *newServer;
	HDD *newHDDInfo;
	struct _ServersCtl *ServersCtl_entry;
	ecb *const ecbp = (ecb *) kep->udata;

	memcpy(user, buf, MAXUSERLEN);
	memcpy(passwd, buf+MAXUSERLEN, MAXPASSLEN);

	if (strcmp(user, configVar[12].value) || strcmp(passwd, configVar[13].value))
	{
	    ecbp->error = 1;	
	    ERROR_ARGS("Authorization from client %s not valid!", inet_ntoa(client));
	    return;
	};

	newServer = xmalloc(sizeof(SInfo), "ServersList");
	memset(newServer, 0, sizeof(SInfo));
	memcpy(newServer, buf+MAXUSERLEN+MAXPASSLEN, sizeof(SInfo));
	int newNumHDD;
	for (newNumHDD=0; newNumHDD < newServer->numHDD; newNumHDD++)
	{
	    newHDDInfo = xmalloc(sizeof(HDD), "HDDInfo");
	    memset(newHDDInfo, 0, sizeof(HDD));
	    memcpy(newHDDInfo, buf+MAXUSERLEN+MAXPASSLEN+sizeof(SInfo)+newNumHDD*sizeof(HDD), sizeof(HDD));
	    newServer->HardDrives[newNumHDD] = newHDDInfo;
	};

	DPRINT_ARGS("INFO FROM %s: user: %s, pass: %s", inet_ntoa(client), user, passwd);
	DPRINT_ARGS("INFO FROM %s: COMPNAME: %s, OS: %s, Release: %s, Motherboard: %s, numCPU: %d, CPU: %s, Memory: %dMb", inet_ntoa(client), newServer->serverName, newServer->OS, newServer->ReleaseOS, newServer->Board, newServer->numCPU, newServer->CPU[0], newServer->memory/1024/1024);
	LIST_FOREACH(ServersCtl_entry, &ServersCtl, ServersCtl_list)
	{
		if(ServersCtl_entry->ip.s_addr==client.s_addr)
		{
		    DPRINT_ARGS("Server %s MODIFY", inet_ntoa(client));	
		    for (newNumHDD=0; newNumHDD < ServersCtl_entry->serverInf->numHDD; newNumHDD++)
			    xfree(ServersCtl_entry->serverInf->HardDrives[newNumHDD]);
		    xfree(ServersCtl_entry->serverInf);
		    ServersCtl_entry->serverInf=newServer;
		    foundServer++;
		    break;
		};
	};
	if (foundServer==0)
	{
	    DPRINT_ARGS("Server %s ADDED", inet_ntoa(client));	
	    ServersCtl_entry = xmalloc(sizeof(struct _ServersCtl), "_ServersCtl");
	    ServersCtl_entry->ip = client;
	    ServersCtl_entry->weight = 500;
	    ServersCtl_entry->serverInf = newServer;
	    LIST_INSERT_HEAD(&ServersCtl, ServersCtl_entry, ServersCtl_list);
	};
};
