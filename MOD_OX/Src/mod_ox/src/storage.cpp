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
* Created by MalinImna <malinimna@gluu.org>
* 
*/

#include "mod_ox.h"
#include "memcache.h"

#define MAX_FILED_LENGTH 2048

static bool memcached_init_flag = false;

using std::string;

int Init_Ox_Storage(const char *memcache_addr, const int memcache_portnum)
{
	if (memcached_init_flag == true)
	{
		return 0;
	}

	if (memcache_init((char *)memcache_addr, memcache_portnum) == 0)
	{
		memcached_init_flag = true;
		return 0;
	}

	return -1;
}

int Set_Ox_Storage(const char *key_name, const char *key_param, const char *val, int lifespan) 
{
	string key;

	if (!key_param)
		return -1;

	if (!key_name)
	{
		key = key_param;
	}
	else
	{
		key = key_name;
		key += ".";
		key += key_param;
	}

	// lifespan will be 0 if not specified by user in config - so lasts as long as browser is open.  In this case, make it last for up to a week.
	time_t expires_on = (lifespan <= 0) ? (86400*30) : (lifespan);
	memcache_delete(key.c_str());
	if (memcache_set_timeout(key.c_str(), val, (unsigned int)expires_on) == 0)
	{
		return 0;
	}

	return -1;
}

char *Get_Ox_Storage(const char *key_name, const char *key_param) 
{
	string key;

	if (!key_param)
		return NULL;

	if (!key_name)
	{
		key = key_param;
	}
	else
	{
		key = key_name;
		key += ".";
		key += key_param;
	}

	char *val = memcache_get(key.c_str());
	if(val == NULL) 
		return NULL;

	char *retString = NULL;
	retString = (char *)malloc(MAX_FILED_LENGTH);
	if (retString == NULL) return NULL;
	
	strcpy(retString, val);

	return retString;
}

int Remove_Ox_Storage(const char *key_name, const char *key_param) 
{
	return Set_Ox_Storage(key_name, key_param, " ", 1);
}

void Close_Ox_Storage()
{
	memcache_destroy();
}
