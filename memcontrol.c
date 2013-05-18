#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <pthread.h>
#include <sys/mman.h>

#include "include/common.h"
extern pthread_mutex_t connectMutex;
void *
xmalloc (unsigned long const size, char *label)
{
	void *result = NULL;
	_malloc_options = "U";

	result = malloc(size);
	return result;
}

void 
xfree (void *ptr)
{
	if (!ptr)
		return;
	free(ptr);
};

void 
xfree_all (void)
{
	struct xmemctl *xmemctl_entry;
	LIST_FOREACH(xmemctl_entry, &memctl, xmemctl_list)
	{
#ifdef DEBUGMALLOC	
	    DPRINT_ARGS("MEMFREEALL: %p size %ld label %s", xmemctl_entry->ptr, xmemctl_entry->size, xmemctl_entry->label);
#endif
	    LIST_REMOVE(xmemctl_entry, xmemctl_list);
#ifdef USEMMAP	
	    munmap(xmemctl_entry, xmemctl_entry->size);
#else
	    free(xmemctl_entry);
#endif
	    //xmemctl_entry=NULL;
	};
};

void *
xrealloc (void *ptr, unsigned long const size)
{
	void *result=NULL;
	result = realloc (ptr, size);
	return result;
}
