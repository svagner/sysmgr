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

#ifdef USEMMAP	
	result = mmap (NULL, size, PROT_READ|PROT_WRITE, MAP_ANONYMOUS, -1, (off_t)0);
#else
	result = malloc(size);
#endif
	struct xmemctl *entry;

	if (!result)
		FATAL_ARGS("Memory exhausted %s. %s", label, strerror(errno));
#ifdef USEMMAP	
	entry = mmap (NULL, sizeof(struct xmemctl), PROT_READ|PROT_WRITE, MAP_ANONYMOUS, -1, (off_t)0);
#else
	entry = malloc(sizeof(struct xmemctl));
#endif
	entry->ptr = result;
	strcpy(entry->label, label);
	entry->size = size;
	LIST_INSERT_HEAD(&memctl, entry, xmemctl_list);
#ifdef DEBUGMALLOC	
	DPRINT_ARGS("MALLOC: %p size %ld label %s", entry->ptr, entry->size, label);
#endif
	return result;
}

void 
xfree (void *ptr)
{
	if (!ptr)
		return;
	struct xmemctl *xmemctl_entry;
	LIST_FOREACH(xmemctl_entry, &memctl, xmemctl_list)
	{
#ifdef DEBUGMALLOC	
			DPRINT_ARGS("MEM FOUND: %p size %ld label %s", xmemctl_entry->ptr, xmemctl_entry->size, xmemctl_entry->label);
#endif
		if (xmemctl_entry->ptr==ptr)
		{
#ifdef DEBUGMALLOC	
			DPRINT_ARGS("MEMFREE: %p size %ld label %s", ptr, xmemctl_entry->size, xmemctl_entry->label);
#endif
			LIST_REMOVE(xmemctl_entry, xmemctl_list);
#ifdef USEMMAP	
			munmap(xmemctl_entry, xmemctl_entry->size);
#else
			free(xmemctl_entry);
#endif
			xmemctl_entry=NULL;
			break;
		};
	};

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
	struct xmemctl *xmemctl_entry, *entry;
	void *result = NULL;

#ifndef USEMMAP	
	result = realloc (ptr, size);
#endif
	int i = 0;


	LIST_FOREACH(xmemctl_entry, &memctl, xmemctl_list)
	{
		if (xmemctl_entry->ptr==ptr)
		{
#ifdef USEMMAP	
			result = xmalloc(size, xmemctl_entry->label);
			memcpy(result, ptr, xmemctl_entry->size);
#endif
#ifdef DEBUGMALLOC	
			DPRINT_ARGS("[ID:%d] MEMREALLOC: %p size %ld to %d", i, ptr, xmemctl_entry->size, size);
#endif

#ifdef USEMMAP	
			xfree(xmemctl_entry);
#else
			LIST_REMOVE(xmemctl_entry, xmemctl_list);
			free(xmemctl_entry);
#endif
			xmemctl_entry=NULL;
			entry = xmalloc(sizeof(struct xmemctl), "reallocated");
			entry->ptr = result;
			entry->size = size;
			LIST_INSERT_HEAD(&memctl, entry, xmemctl_list);
#ifdef DEBUGMALLOC	
			DPRINT_ARGS("%p size %ld", entry, entry->size);
#endif
			return result;
		};
		i++;
	};
	if (!result)
		FATAL("Memory exhausted");
	return result;
}
