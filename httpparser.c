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


#include "include/common.h"
#include "include/net.h"
#include "include/http_parser.h"
#include "include/http_pages.h"
#include "include/sysproto.h"

int
parse_http_request(struct kevent *kephttp, char *buf)
{
    if (strlen(buf)<1)
	    return -1;
    ecbhttp *ecbp = (ecbhttp *) kephttp->udata;
    const char *sep = "\n";	
    char * pch;
    char test[100];
    int result;
    http_request *request;

    pch = strtok(buf, sep);
    
    request = (http_request *) xmalloc (sizeof(http_request), "httprequest");
    memset(request, 0, sizeof(http_request));
    DPRINT_ARGS("MALLOC ecbp->req %p", ecbp->req);
    ecbp->req=request;
    DPRINT_ARGS("MALLOC ecbp->req %p", ecbp->req);

    while (pch!=NULL)
    {
	result=sscanf(pch, "GET %s HTTP*", ecbp->req->path);
	if (result==1)
	    DPRINT_ARGS("PATH: %s\n", ecbp->req->path);
	pch = strtok(NULL, sep);
    };
    return 0;
};

int
get_response(char *bufout, struct kevent *kephttp, int page_is_read)
{
    ecbhttp *ecbp = (ecbhttp *) kephttp->udata;
    struct adminAccess *adminAccess_entry;
    struct _ServersCtl *ServersCtl_entry;

	    char *buffer=NULL;
	    int cnt=0;
	    int sizeOfOut, sizeOfSInfo, sizeOfHDD;
	    char memory[100];
	    int cpunum;
	    int hddcnt;

    if (kephttp==NULL || kephttp==0 || !ecbp->req->path || ecbp->req==NULL || ecbp->req==0)
	    return -1;

//    if (!strncmp(STATICDIR, ecbp->req->path, strlen(STATICDIR)) && strlen(ecbp->req->path)>strlen(STATICDIR))
    if (!strncmp(STATICDIR, ecbp->req->path, strlen(STATICDIR)))
    {
	    sprintf(bufout, "%s%s", configVar[8].value, ecbp->req->path);
	    return 202;
    };

    if (!strcmp("/admin", ecbp->req->path) || !strcmp("/admin/", ecbp->req->path))
    {
	    LIST_FOREACH(adminAccess_entry, &adminAccessCtl, adminAccess_list)
	    {
		DPRINT_ARGS("COUNT ADMINS: %d", cnt);    
		/* malloc memory for buffer */    
		if (cnt==0)
		{
		    sizeOfOut = 21+strlen(inet_ntoa(adminAccess_entry->ip))+strlen(adminAccess_entry->login);
		    buffer = xmalloc(sizeOfOut, "http_parce_buf");    
		    bzero(buffer, sizeOfOut);
		    DPRINT_ARGS("ALLOCATED %d", sizeOfOut);
		}
		else
		{
		    DPRINT_ARGS("[%d:%d] Realloc from %d to %d", cnt, kephttp->ident, strlen(buffer), 20+strlen(inet_ntoa(adminAccess_entry->ip))+strlen(adminAccess_entry->login));	
		    buffer = xrealloc(buffer, strlen(buffer) + strlen(inet_ntoa(adminAccess_entry->ip))+strlen(adminAccess_entry->login)+21);	
		    DPRINT_ARGS("%s", adminAccess_entry->login);
		};
		strcat(buffer, "{ip: '");
		strcat(buffer, inet_ntoa(adminAccess_entry->ip));
		strcat(buffer, "', login: '");
		strcat(buffer, adminAccess_entry->login);
		strcat(buffer, "'},");
		cnt++;
	    };
	    DPRINT_ARGS("BUFFER: %s", buffer);
	    if (!cnt)
	    {
		    xfree(buffer);
		    return 0;
	    };
	    cnt=0;
//	    sizeOfOut = strlen(pageAdmin)-strlen("$buffer$")+strlen(buffer)+100;
//	    char outbuf[sizeOfOut];
//	    str_replace(outbuf, pageAdmin, "$buffer$", buffer);

//	    sprintf(bufout, "%s%zd\n\n%s", HEAD200, strlen(outbuf), outbuf);
	    sprintf(bufout, "%s%zd\n\n%s", HEAD200, strlen(buffer), buffer);
	    NOTICE_ARGS("%s GET %s CODE 200", inet_ntoa(ecbp->client->ip), ecbp->req->path);
	    xfree(buffer);
	    return 200;
    }
    /* List all Servers */
    else if (!strcmp("/servers", ecbp->req->path) || !strcmp("/servers/", ecbp->req->path))
    {
	    LIST_FOREACH(ServersCtl_entry, &ServersCtl, ServersCtl_list)
	    {
		sizeOfHDD=0;
		for (hddcnt=0; hddcnt < ServersCtl_entry->serverInf->numHDD; hddcnt++)
		{
			sizeOfHDD=sizeOfHDD+strlen(ServersCtl_entry->serverInf->HardDrives[hddcnt]->vendor)+strlen(ServersCtl_entry->serverInf->HardDrives[hddcnt]->product)+strlen(ServersCtl_entry->serverInf->HardDrives[hddcnt]->revision)+strlen(ServersCtl_entry->serverInf->HardDrives[hddcnt]->device);
		}
		//81 is work without HDD
		sprintf(memory, "%ldMb", ServersCtl_entry->serverInf->memory/1024/1024);	
		sizeOfSInfo = 91+26+400+ServersCtl_entry->serverInf->numCPU*4+strlen(inet_ntoa(ServersCtl_entry->ip))+strlen(ServersCtl_entry->serverInf->serverName)+strlen(ServersCtl_entry->serverInf->CPU[0])+strlen(ServersCtl_entry->serverInf->Board)+strlen(memory)+strlen(ServersCtl_entry->serverInf->OS)+strlen(ServersCtl_entry->serverInf->ReleaseOS)+sizeOfHDD;    
		DPRINT_ARGS("COUNT Servers: %d", cnt);    
		/* malloc memory for buffer */    
		if (cnt==0)
		{
		//    sprintf(memory, "%ldMb", ServersCtl_entry->serverInf->memory/1024/1024);	
		    buffer = xmalloc(sizeOfSInfo+18, "http_servers_buf");    
		    bzero(buffer, sizeOfSInfo+18);
		    DPRINT_ARGS("ALLOCATED %d", sizeOfSInfo);
		}
		else
		{
		    strcat(buffer, ", ");
		    buffer = xrealloc(buffer, strlen(buffer) + sizeOfSInfo+18);
		};
		strcat(buffer, "{\"ip\": \"");
		strcat(buffer, inet_ntoa(ServersCtl_entry->ip));
		strcat(buffer, "\", \"name\": \"");
		strcat(buffer, ServersCtl_entry->serverInf->serverName);
		strcat(buffer, "\", \"CPU\": [ ");
		for (cpunum = 0; cpunum< ServersCtl_entry->serverInf->numCPU; cpunum++)
		{
		    if (cpunum>0)	
			strcat(buffer, ", ");
		    strcat(buffer, "\"");
		    strcat(buffer, ServersCtl_entry->serverInf->CPU[cpunum]);
		    strcat(buffer, "\"");

		}
		strcat(buffer, "], \"HDDS\": [ ");
		for (hddcnt = 0; hddcnt < ServersCtl_entry->serverInf->numHDD; hddcnt++)
		{
		    if (hddcnt)
			strcat(buffer, ",");
		    strcat(buffer, " \"");
		    strcat(buffer, ServersCtl_entry->serverInf->HardDrives[hddcnt]->product);
		    strcat(buffer, "\" ");

		};
		strcat(buffer, "], ");

		for (hddcnt = 0; hddcnt < ServersCtl_entry->serverInf->numHDD; hddcnt++)
		{
		    strcat(buffer, "\"");	
		    strcat(buffer, ServersCtl_entry->serverInf->HardDrives[hddcnt]->product);
		    strcat(buffer, "\": { ");	
		    strcat(buffer, "\"vendor\": \"");	
		    strcat(buffer, ServersCtl_entry->serverInf->HardDrives[hddcnt]->vendor);
		    strcat(buffer, "\", \"product\": \"");
		    strcat(buffer, ServersCtl_entry->serverInf->HardDrives[hddcnt]->product);
		    strcat(buffer, "\", \"revision\": \"");
		    strcat(buffer, ServersCtl_entry->serverInf->HardDrives[hddcnt]->revision);
		    strcat(buffer, "\", \"device\": \"");
		    strcat(buffer, ServersCtl_entry->serverInf->HardDrives[hddcnt]->device);
		    strcat(buffer, "\" }, ");
		};

		strcat(buffer, "\"Mothreboard\": \"");
		strcat(buffer, ServersCtl_entry->serverInf->Board);
		strcat(buffer, "\", \"Memory\": \"");
		strcat(buffer, memory);

		strcat(buffer, "\", \"OS\": \"");
		strcat(buffer, ServersCtl_entry->serverInf->OS);
		strcat(buffer, "\", \"ReleaseOS\": \"");
		strcat(buffer, ServersCtl_entry->serverInf->ReleaseOS);

		strcat(buffer, "\"} ");
		cnt++;
	    };
	    DPRINT_ARGS("BUFFER: %s", buffer);
	    if (!cnt)
	    {
		sprintf(bufout, "%s%zd\n\n%s", HEAD404, strlen(page404)+1, page404);
		NOTICE_ARGS("%s GET %s CODE 404", inet_ntoa(ecbp->client->ip), ecbp->req->path);
		xfree(buffer);
		return 404;
	    };
	    cnt=0;
//	    sizeOfOut = strlen(pageAdmin)-strlen("$buffer$")+strlen(buffer)+100;
//	    char outbuf[sizeOfOut];
//	    str_replace(outbuf, pageAdmin, "$buffer$", buffer);

//	    sprintf(bufout, "%s%zd\n\n%s", HEAD200, strlen(outbuf), outbuf);
	    sprintf(bufout, "%s%zd\n\n%s", HEAD200, strlen(buffer), buffer);
	    NOTICE_ARGS("%s GET %s CODE 200", inet_ntoa(ecbp->client->ip), ecbp->req->path);
	    xfree(buffer);
	    return 200;
    }
    else if (!strncmp("/servers/?", ecbp->req->path, 10) || !strncmp("/servers?", ecbp->req->path, 9))
    {
	const char *sep = "?";	
	char options[50];
	int result;

	result=sscanf(ecbp->req->path, "/servers?%s", options);
	if (result!=1)
		result=sscanf(ecbp->req->path, "/servers/?%s", options);
	if (result!=1)
	{
		sprintf(bufout, "%s%zd\n\n111%s", HEAD404, strlen(page404)+1, page404);
		NOTICE_ARGS("%s GET %s CODE 404", inet_ntoa(ecbp->client->ip), ecbp->req->path);
		return 404;
	}
	LIST_FOREACH(ServersCtl_entry, &ServersCtl, ServersCtl_list)
	{
	    if (!strcmp(ServersCtl_entry->serverInf->serverName, options))
	    {
		if (cnt==0)
		{
		    sprintf(memory, "%ldMb", ServersCtl_entry->serverInf->memory/1024/1024);	
		    buffer = xmalloc(5000, "http_servers_buf");    
		    bzero(buffer, 5000);
		    DPRINT_ARGS("ALLOCATED %d", sizeOfSInfo);
		}
		else
		    strcat(buffer, ", ");
		strcat(buffer, "{\"ip\": \"");
		strcat(buffer, inet_ntoa(ServersCtl_entry->ip));
		strcat(buffer, "\", \"name\": \"");
		strcat(buffer, ServersCtl_entry->serverInf->serverName);
		strcat(buffer, "\", \"CPU\": [ ");
		for (cpunum = 0; cpunum< ServersCtl_entry->serverInf->numCPU; cpunum++)
		{
		    if (cpunum>0)	
		    strcat(buffer, ", ");
		    strcat(buffer, "\"");
		    strcat(buffer, ServersCtl_entry->serverInf->CPU[cpunum]);
		    strcat(buffer, "\"");

		}
		strcat(buffer, "], \"HDDS\": [ ");
		for (hddcnt = 0; hddcnt < ServersCtl_entry->serverInf->numHDD; hddcnt++)
		{
		    if (hddcnt)
			strcat(buffer, ",");
		    strcat(buffer, " \"");
		    strcat(buffer, ServersCtl_entry->serverInf->HardDrives[hddcnt]->product);
		    strcat(buffer, "\" ");

		};
		strcat(buffer, "], ");

		for (hddcnt = 0; hddcnt < ServersCtl_entry->serverInf->numHDD; hddcnt++)
		{
		    strcat(buffer, "\"");	
		    strcat(buffer, ServersCtl_entry->serverInf->HardDrives[hddcnt]->product);
		    strcat(buffer, "\": { ");	
		    strcat(buffer, "\"vendor\": \"");	
		    strcat(buffer, ServersCtl_entry->serverInf->HardDrives[hddcnt]->vendor);
		    strcat(buffer, "\", \"product\": \"");
		    strcat(buffer, ServersCtl_entry->serverInf->HardDrives[hddcnt]->product);
		    strcat(buffer, "\", \"revision\": \"");
		    strcat(buffer, ServersCtl_entry->serverInf->HardDrives[hddcnt]->revision);
		    strcat(buffer, "\", \"device\": \"");
		    strcat(buffer, ServersCtl_entry->serverInf->HardDrives[hddcnt]->device);
		    strcat(buffer, "\" }, ");
		};

		strcat(buffer, "\"Mothreboard\": \"");
		strcat(buffer, ServersCtl_entry->serverInf->Board);
		strcat(buffer, "\", \"Memory\": \"");
		strcat(buffer, memory);

		strcat(buffer, "\", \"OS\": \"");
		strcat(buffer, ServersCtl_entry->serverInf->OS);
		strcat(buffer, "\", \"ReleaseOS\": \"");
		strcat(buffer, ServersCtl_entry->serverInf->ReleaseOS);

		strcat(buffer, "\"} ");
		cnt++;
		break;
	    };
	};
	    DPRINT_ARGS("BUFFER: %s", buffer);
	    if (!cnt)
	    {
		xfree(buffer);
		sprintf(bufout, "%s%zd\n\n%s", HEAD404, strlen(page404), page404);
		NOTICE_ARGS("%s GET %s CODE 404", inet_ntoa(ecbp->client->ip), ecbp->req->path);

		return 404;
	    };
	    cnt=0;
	    sprintf(bufout, "%s%zd\n\n%s", HEAD200, strlen(buffer), buffer);
	    NOTICE_ARGS("%s GET %s CODE 200", inet_ntoa(ecbp->client->ip), ecbp->req->path);
	    xfree(buffer);
	    return 200;

    }
    else
    {
	    sprintf(bufout, "%s%zd\n\n%s", HEAD404, strlen(page404), page404);
	    NOTICE_ARGS("%s GET %s CODE 404", inet_ntoa(ecbp->client->ip), ecbp->req->path);
	    return 404;
    }
    return 0;
}

int 
str_replace(char *output, char *input, char *sWhat, char *sWith)
{
	int sizetmp;
	sizetmp = strlen(input)-strlen(sWhat)+strlen(sWith);
	char res[sizetmp], *a=input, *b=output;
	for(; (*b=*a); ++a, ++b){
		if(!strncmp(a, sWhat, strlen(sWhat))){
			strcpy(b, sWith);
			a+=strlen(sWhat)-1;
			b+=strlen(sWith)-1;
		}
	}
	output = res;
	return 0;
}
