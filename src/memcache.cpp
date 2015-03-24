/* Copyright (C) 2007-2011 Gluu (http://ox.gluu.org/doku.php?id=oxd:mod_ox)
*
* Permission is hereby granted, free of charge, to any person
* obtaining a copy of this software and associated documentation
* files (the "Software"), to deal in the Software without
* restriction, including without limitation the rights to use,
* copy, modify, merge, publish, distribute, sublicense, and/or sell
* copies of the Software, and to permit persons to whom the
* Software is furnished to do so, subject to the following
* conditions:
* 
* The above copyright notice and this permission notice shall be
* included in all copies or substantial portions of the Software.
*
* THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
* EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
* OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
* NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
* HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
* WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
* FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
* OTHER DEALINGS IN THE SOFTWARE.
* 
* Created by MalinImna <imna@gluu.org>
* 
*/

#include "memcache.h"
#include <stdlib.h>
#include "mod_ox.h"

static apr_pool_t *MemcachePool = NULL;
static apr_memcache_t *Memcache = NULL;
#define UNTIL	3600
int memcache_init(const char *host_name, const int port_num)
{
	apr_status_t rv;
	apr_memcache_server_t *server;
	apr_memcache_stats_t* stats;
	char *result;
	apr_uint32_t until = 600;

	if ((host_name==NULL) || port_num < 1)
		return -1;

	if (MemcachePool != NULL)
	{
		apr_pool_destroy(MemcachePool);
		MemcachePool = NULL;
	}
	
	apr_initialize();
	atexit(apr_terminate);
	apr_pool_create(&MemcachePool, NULL);

	rv = apr_memcache_create(MemcachePool, 10, 0, &Memcache);
	if (rv) goto MEMCACHE_INIT_EXIT;

	rv = apr_memcache_server_create(MemcachePool, host_name, port_num, 0, 1, 1, 60, &server);
	if (rv) goto MEMCACHE_INIT_EXIT;

	rv = apr_memcache_add_server(Memcache, server);
	if (rv) goto MEMCACHE_INIT_EXIT;

	rv = apr_memcache_version(server, MemcachePool, &result);
	if (rv) goto MEMCACHE_INIT_EXIT;

	rv = apr_memcache_stats(server, MemcachePool, &stats);
	if (rv) goto MEMCACHE_INIT_EXIT;

	return 0;

MEMCACHE_INIT_EXIT:
	if (MemcachePool != NULL)
	{
		apr_pool_destroy(MemcachePool);
		MemcachePool = NULL;
	}

	return -1;
}

int memcache_set(const char *key, const char *value)
{
	apr_status_t rv;
	rv = apr_memcache_set(Memcache, key, (char *)value, strlen(value), UNTIL, 0);

	return rv;
}

int memcache_set_timeout(const char *key, const char *value, unsigned int timeout)
{
	apr_status_t rv;
	rv = apr_memcache_set(Memcache, key, (char *)value, strlen(value), (apr_uint32_t)timeout, 0);

	return rv;
}

char* memcache_get(const char *key)
{
	apr_status_t rv;
	apr_size_t len;
	char *result;

	rv = apr_memcache_getp(Memcache, MemcachePool, key, &result, &len, NULL);

	if (rv == 0)
	{
		return result;
	} 
	else
	{
		return NULL;
	}
}

int memcache_delete(const char *key)
{
	apr_status_t rv;
	rv = apr_memcache_delete(Memcache, key, 100);

	return rv;
}

void memcache_destroy(void)
{
	if (MemcachePool != NULL)
	{
		apr_pool_destroy(MemcachePool);
		MemcachePool = NULL;
	}
}
