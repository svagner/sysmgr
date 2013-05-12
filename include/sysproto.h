#include <sys/queue.h>

/* Header 100 bytes */
#define MAXUSERLEN      20
#define MAXPASSLEN      80

#define MAXSERVERNAME	100
#define MAXCPUINFO	100
#define MAXBOARDINFO	100
#define MAXOSNAME	20
#define MAXRELEASEINFO	256
#define MAXCPUS         16

/* For HDD */
#define MAXHDDS         16
#define MAXHDDINFO      100
#define MAXVENDORINFO   20
#define MAXPRODUCTINFO  20
#define MAXREVISIONINFO 20
#define MAXHDDDEVICENAME 5

typedef struct ErrCode {
	int id;
	char *value;
} Errors;
/* ErrorCode */
extern Errors ErrCodes[];

typedef struct HDDInfo {
	char vendor[MAXVENDORINFO];
	char product[MAXPRODUCTINFO];
	char revision[MAXREVISIONINFO];
	char device[MAXHDDDEVICENAME];
	int scbus;
	int target;
	int lun;
} HDD;

typedef struct ServerInfo {
	char serverName[MAXSERVERNAME];
	int numCPU;
	char CPU[MAXCPUS][MAXCPUINFO];
	char Board[MAXCPUINFO];
	unsigned long  memory;
	char OS[MAXOSNAME];
	char ReleaseOS[MAXRELEASEINFO];
	int numHDD;
	HDD *HardDrives[MAXHDDS];
} SInfo;

LIST_HEAD(Servers_head, _ServersCtl) ServersCtl;

struct _ServersCtl
{
    struct in_addr ip;
    unsigned int weight; // default = 500, max = 5000
    SInfo *serverInf;
    LIST_ENTRY(_ServersCtl) ServersCtl_list;
};
