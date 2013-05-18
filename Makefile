.include <bsd.own.mk>

PROG=   sysmgr
MAN=    sysmgr.1
SRCS=    syscommands.c syshandler.c httphandler.c memcontrol.c logger.c conf.c netapi.c sysmgr.c \
	httpparser.c crypto.c
CFLAGS+= -ggdb -Iinclude -lutil -lc -lpthread -lssl
#CFLAGS+= -DDEBUG -DDEBUGMALLOC -DUSEMMAP
#CFLAGS+= -DDEBUG -DDEBUGMALLOC

.include <bsd.prog.mk>
