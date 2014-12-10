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

#include <stdio.h>

#include "mod_ox.h"
#include "oxd_client.h"
#include "oxd_main.h"

//////////////////////////////////////////////////////////////////////////
///  Group of functions for oxd communication 
/*
* Discovery and Register Client with oxd
* http://ox.gluu.org/doku.php?id=oxd:communication_protocol#discovery
* http://ox.gluu.org/doku.php?id=oxd:communication_protocol#register_client
*/
int ox_discovery(mod_ox_config *s_cfg)
{
#define BUF_SIZE 8192
	char responseStr[BUF_SIZE];
	char keyValue[BUF_SIZE];
	char deserializeStr[BUF_SIZE];
	double keyIntValue;
	int ret;
	int responseLen;
	char tmp[5];

	ret = oxd_discovery(s_cfg->oxd_hostaddr, s_cfg->oxd_portnum, s_cfg->discovery_url, responseStr);
	if (ret == RET_FAILURE)
		return -1;

	memcpy(tmp, responseStr, 4); tmp[4] = 0;
	responseLen = atoi(tmp);
	if (libjson_init(&responseStr[4], responseLen) == RET_SUCCESS)
	{
		if (libjson_getKeyValue("status", keyValue, BUF_SIZE) == RET_SUCCESS)
		{
			if (strcmp(keyValue, "ok"))
				return -1;
		}

		if (libjson_getKeyValue("data.issuer", keyValue, BUF_SIZE) == RET_SUCCESS)
		{
			Set_Ox_Storage(s_cfg->client_name, "oxd.issuer", keyValue, 0);
		}

		if (libjson_getKeyValue("data.authorization_endpoint", keyValue, BUF_SIZE) == RET_SUCCESS)
		{
			Set_Ox_Storage(s_cfg->client_name, "oxd.authorization_endpoint", keyValue, 0);
		}

		if (libjson_getKeyValue("data.token_endpoint", keyValue, BUF_SIZE) == RET_SUCCESS)
		{
			Set_Ox_Storage(s_cfg->client_name, "oxd.token_endpoint", keyValue, 0);
		}
	}
	else
	{
		return -1;
	}

	std::string redirect_uri = s_cfg->login_url;
	redirect_uri += "redirect";
	if (s_cfg->logoutredirect_url)
		ret = oxd_register_client(s_cfg->oxd_hostaddr, s_cfg->oxd_portnum, s_cfg->discovery_url, redirect_uri.c_str(), s_cfg->logoutredirect_url, s_cfg->client_name, responseStr);
	else
		ret = oxd_register_client(s_cfg->oxd_hostaddr, s_cfg->oxd_portnum, s_cfg->discovery_url, redirect_uri.c_str(), "", s_cfg->client_name, responseStr);
	
	if (ret == RET_FAILURE)
		return -1;

	memcpy(tmp, responseStr, 4); tmp[4] = 0;
	responseLen = atoi(tmp);
	if (libjson_init(&responseStr[4], responseLen) == RET_SUCCESS)
	{
		if (libjson_getKeyValue("status", keyValue, BUF_SIZE) == RET_SUCCESS)
		{
			if (strcmp(keyValue, "ok"))
				return-1;
		}
		else
		{
			return -1;
		}

		keyIntValue = 0;
		int timeout;
		if (libjson_getKeyValue("data.client_secret_expires_at", &keyIntValue) == RET_SUCCESS)
		{
			time_t rawtime;
			time (&rawtime);
			if (rawtime < (time_t)keyIntValue)
				timeout = (int)((time_t)keyIntValue-rawtime);
			else
				timeout = 0;
		}
		else
		{
			return -1;
		}

		if (libjson_getKeyValue("data.client_id", keyValue, BUF_SIZE) == RET_SUCCESS)
			Set_Ox_Storage(s_cfg->client_name, "oxd.client_id", keyValue, timeout);
		else
			return -1;

		if (libjson_getKeyValue("data.client_secret", keyValue, BUF_SIZE) == RET_SUCCESS)
			Set_Ox_Storage(s_cfg->client_name, "oxd.client_secret", keyValue, timeout);
		else
			return -1;

		if (libjson_getKeyValue("data.registration_access_token", keyValue, BUF_SIZE) == RET_SUCCESS)
			Set_Ox_Storage(s_cfg->client_name, "oxd.registration_access_token", keyValue, timeout);
		else
			return -1;
	}
	else
	{
		return -1;
	}

	// Save Client info into filesystem
	if (s_cfg->credit_path)
	{
		if (libjson_deserialize(&responseStr[4], responseLen, deserializeStr, BUF_SIZE) != -1)
		{
			FILE *fp;
			fp = fopen(s_cfg->credit_path, "w");
			if (fp != NULL)
			{
				fwrite(deserializeStr, 1, strlen(deserializeStr), fp);
				fclose(fp);
			}
		}
	}
	
	return 0;
}

/*
* Check status of ID Token
* http://ox.gluu.org/doku.php?id=oxd:communication_protocol#check_status_of_id_token
*/
int ox_check_id_token(mod_ox_config *s_cfg, const char *id_token, const char *session_id)
{
#define BUF_SIZE 8192
	char responseStr[BUF_SIZE];
	char keyValue[BUF_SIZE];
	int ret;
	int responseLen;
	double keyIntValue;
	char tmp[5];
	int timeout;

	if (id_token==NULL)
		return -1;

	ret = oxd_check_id_token(s_cfg->oxd_hostaddr, s_cfg->oxd_portnum, s_cfg->discovery_url, id_token, responseStr);
	if (ret == RET_FAILURE)
		return -1;

	memcpy(tmp, responseStr, 4);
	tmp[4] = 0;
	responseLen = atoi(tmp);
	if (libjson_init(&responseStr[4], responseLen) == RET_SUCCESS)
	{
		if (libjson_getKeyValue("status", keyValue, BUF_SIZE) == RET_SUCCESS)
		{
			if (strcmp(keyValue, "ok"))
				return -1;
		}
		else
			return -1;
		
		bool keyBoolValue=false;
		if (libjson_getKeyValue("data.active", &keyBoolValue) == RET_SUCCESS)
		{
			if (keyBoolValue != true)
				return -1;
		}
		else
			return -1;
/*
		// Check auth mode
		if (libjson_getKeyValue("data.claims.amr[0]", keyValue, BUF_SIZE) == RET_SUCCESS)
		{
			if (s_cfg->requested_acr)
			{
				if (strcmp(keyValue, s_cfg->requested_acr))
					return -1;
			}
		}
		else
			return -1;
*/

		// Set timeout
		keyIntValue = 0;
		if (libjson_getKeyValue("data.expires_at", &keyIntValue) == RET_SUCCESS)
		{
			time_t rawtime;
			time (&rawtime);
			if (rawtime < (time_t)keyIntValue)
				timeout = (int)((time_t)keyIntValue-rawtime);
			else
				timeout = 0;

			if (timeout <= 0)
				return -1;

		}
		else
		{
			return -1;
		}

		// Check Client ID
		if (libjson_getKeyValue("data.claims.aud[0]", keyValue, BUF_SIZE) == RET_SUCCESS)
		{
			char *client_id = Get_Ox_Storage(s_cfg->client_name, "oxd.client_id");
			if (!client_id)	return -1;

			if (strcmp(keyValue, client_id))
			{
				free(client_id);
				return -1;
			}
			free(client_id);
		}
		else
			return -1;

		// Get User Claims
		char *token[MAX_ATTR_NUM];
		char uma_claims_str[1024];
		int i = 0;
		std::string attr_name;

		for (i=0; i<MAX_ATTR_NUM; i++)
			token[i] = NULL;

		strcpy(uma_claims_str, s_cfg->uma_sent_user_claims);
		i = 0;
		token[i] = strtok(uma_claims_str, "+");
		while(token[i]!= NULL) 
		{
			i++; if (i >= MAX_ATTR_NUM) break;		
			token[i] = strtok(NULL, "+");
		}

		i = 0;
		while(token[i]!= NULL) 
		{
			attr_name = "data";
			attr_name += ".";
			attr_name += "claims";
			attr_name += ".";
			attr_name += token[i];
			attr_name += "[0]";

			if (libjson_getKeyValue((char *)attr_name.c_str(), keyValue, BUF_SIZE) == RET_SUCCESS)
			{
				std::string id = session_id;
				id += ".";
				id += token[i];
				Set_Ox_Storage(NULL, id.c_str(), keyValue, timeout);
			}

			i++; if (i >= MAX_ATTR_NUM) break;		
		}

		return timeout;
	}

	return -1;
}

/*
* Obtain PAT
* http://ox.gluu.org/doku.php?id=oxd:communication_protocol#obtain_pat
*/
int ox_obtain_pat(mod_ox_config *s_cfg)
{
#define BUF_SIZE 8192
	char responseStr[BUF_SIZE];
	char keyValue[BUF_SIZE];
	double keyIntValue;
	int ret;
	int responseLen;
	char tmp[5];

	char *client_id = Get_Ox_Storage(s_cfg->client_name, "oxd.client_id");
	char *client_secret = Get_Ox_Storage(s_cfg->client_name, "oxd.client_secret");
	char *user_id = "";
	char *user_secret = "";

	std::string redirect_uri = s_cfg->login_url;
	redirect_uri += "redirect";
	ret = oxd_obtain_pat(s_cfg->oxd_hostaddr, s_cfg->oxd_portnum, \
		s_cfg->discovery_url, s_cfg->uma_discovery_url, redirect_uri.c_str(), \
		client_id, client_secret, user_id, user_secret, responseStr);

	if (client_id) free(client_id);
	if (client_secret) free(client_secret);

	if (ret == RET_FAILURE)
		return -1;

	memcpy(tmp, responseStr, 4); tmp[4] = 0;
	responseLen = atoi(tmp);
	if (libjson_init(&responseStr[4], responseLen) == RET_SUCCESS)
	{
		if (libjson_getKeyValue("status", keyValue, BUF_SIZE) == RET_SUCCESS)
		{
			if (strcmp(keyValue, "ok"))
				return -1;
		}
		else
		{
			return -1;
		}

		keyIntValue = 0;
		int timeout;
		if (libjson_getKeyValue("data.expires_in_seconds", &keyIntValue) == RET_SUCCESS)
			timeout = (int)keyIntValue;
		else
			return -1;

		if (libjson_getKeyValue("data.pat_token", keyValue, BUF_SIZE) == RET_SUCCESS)
			Set_Ox_Storage(s_cfg->client_name, "uma.pat_token", keyValue, timeout);
		else
			return -1;
/*
		if (libjson_getKeyValue("data.pat_refresh_token", keyValue, BUF_SIZE) == RET_SUCCESS)
			Set_Ox_Storage(s_cfg->client_name, "uma.pat_refresh_token", keyValue, timeout);
		else
			return -1;

		if (libjson_getKeyValue("data.authorization_code", keyValue, BUF_SIZE) == RET_SUCCESS)
			Set_Ox_Storage(s_cfg->client_name, "uma.authorization_code", keyValue, timeout);
		else
			return -1;
*/
	}
	else
	{
		return -1;
	}

	return 0;
}

/*
* Register Resource
* http://ox.gluu.org/doku.php?id=oxd:communication_protocol#register_resource
*/
int ox_register_resources(mod_ox_config *s_cfg)
{
#define BUF_SIZE 8192
	char responseStr[BUF_SIZE];
	char keyValue[BUF_SIZE];
	int ret;
	int responseLen;
	char tmp[5];
	int i;

	char *pat_token = Get_Ox_Storage(s_cfg->client_name, "uma.pat_token");

	if ((s_cfg->uma_am_host[0].host == NULL) || (s_cfg->uma_am_host[0].scope[0] == NULL))
		return -1;

	for (i=0; i<5; i++)
	{
		if (s_cfg->uma_am_host[0].scope[i] == NULL)
			break;
	}
	if (i == 0) return -1;

	const char *res_scope[] = {
		s_cfg->uma_am_host[0].scope[0], 
		s_cfg->uma_am_host[0].scope[1], 
		s_cfg->uma_am_host[0].scope[2], 
		s_cfg->uma_am_host[0].scope[3], 
		s_cfg->uma_am_host[0].scope[4]
	};

	ret = oxd_register_resource(s_cfg->oxd_hostaddr, s_cfg->oxd_portnum, \
		s_cfg->uma_discovery_url, pat_token, s_cfg->uma_resource_name, i, res_scope, responseStr);

	if (pat_token) free(pat_token);

	if (ret == RET_FAILURE)
		return -1;

	memcpy(tmp, responseStr, 4); tmp[4] = 0;
	responseLen = atoi(tmp);
	if (libjson_init(&responseStr[4], responseLen) == RET_SUCCESS)
	{
		if (libjson_getKeyValue("status", keyValue, BUF_SIZE) == RET_SUCCESS)
		{
			if (strcmp(keyValue, "ok"))
				return -1;
		}
		else
		{
			return -1;
		}

		if (libjson_getKeyValue("data._id", keyValue, BUF_SIZE) == RET_SUCCESS)
		{
			std::string id = std::string(s_cfg->uma_resource_name);
			id += "_id";
			Set_Ox_Storage(s_cfg->client_name, id.c_str(), keyValue, 0);
		}
		else
		{
			return -1;
		}

		if (libjson_getKeyValue("data._rev", keyValue, BUF_SIZE) == RET_SUCCESS)
		{
			std::string rev = std::string(s_cfg->uma_resource_name);
			rev += "_rev";
			Set_Ox_Storage(s_cfg->client_name, rev.c_str(), keyValue, 0);
		}
		else
		{
			return -1;
		}
	}
	else
	{
		return -1;
	}

	return 0;
}

/*
* Obtain AAT
* http://ox.gluu.org/doku.php?id=oxd:communication_protocol#obtain_aat
*/
int ox_obtain_aat(mod_ox_config *s_cfg)
{
#define BUF_SIZE 8192
	char responseStr[BUF_SIZE];
	char keyValue[BUF_SIZE];
	double keyIntValue;
	int ret;
	int responseLen;
	char tmp[5];

	char *client_id = Get_Ox_Storage(s_cfg->client_name, "oxd.client_id");
	char *client_secret = Get_Ox_Storage(s_cfg->client_name, "oxd.client_secret");
	char *user_id = "";
	char *user_secret = "";

	std::string redirect_uri = s_cfg->login_url;
	redirect_uri += "redirect";
	ret = oxd_obtain_aat(s_cfg->oxd_hostaddr, s_cfg->oxd_portnum, \
		s_cfg->discovery_url, s_cfg->uma_discovery_url, redirect_uri.c_str(), \
		client_id, client_secret, user_id, user_secret, responseStr);

	if (client_id) free(client_id);
	if (client_secret) free(client_secret);

	if (ret == RET_FAILURE)
		return -1;

	memcpy(tmp, responseStr, 4); tmp[4] = 0;
	responseLen = atoi(tmp);
	if (libjson_init(&responseStr[4], responseLen) == RET_SUCCESS)
	{
		if (libjson_getKeyValue("status", keyValue, BUF_SIZE) == RET_SUCCESS)
		{
			if (strcmp(keyValue, "ok"))
				return -1;
		}
		else
		{
			return -1;
		}

		keyIntValue = 0;
		int timeout;
		if (libjson_getKeyValue("data.expires_in_seconds", &keyIntValue) == RET_SUCCESS)
			timeout = (int)keyIntValue;
		else
			return -1;

		if (libjson_getKeyValue("data.aat_token", keyValue, BUF_SIZE) == RET_SUCCESS)
			Set_Ox_Storage(s_cfg->client_name, "uma.aat_token", keyValue, timeout);
		else
			return -1;
	}
	else
	{
		return -1;
	}

	return 0;
}

/*
* Obtain RPT
* http://ox.gluu.org/doku.php?id=oxd:communication_protocol#obtain_rpt
*/
int ox_obtain_rpt(mod_ox_config *s_cfg)
{
#define BUF_SIZE 8192
	char responseStr[BUF_SIZE];
	char keyValue[BUF_SIZE];
	int ret;
	int responseLen;
	char tmp[5];

	char *aat_token = Get_Ox_Storage(s_cfg->client_name, "uma.aat_token");

	if ((s_cfg->uma_am_host[0].host == NULL) || (s_cfg->uma_am_host[0].scope[0] == NULL))
		return -1;

	ret = oxd_obtain_rpt(s_cfg->oxd_hostaddr, s_cfg->oxd_portnum, aat_token, s_cfg->uma_am_host[0].host, responseStr);

	if (aat_token) free(aat_token);

	if (ret == RET_FAILURE)
		return -1;

	memcpy(tmp, responseStr, 4); tmp[4] = 0;
	responseLen = atoi(tmp);
	if (libjson_init(&responseStr[4], responseLen) == RET_SUCCESS)
	{
		if (libjson_getKeyValue("status", keyValue, BUF_SIZE) == RET_SUCCESS)
		{
			if (strcmp(keyValue, "ok"))
				return -1;
		}
		else
		{
			return -1;
		}

		if (libjson_getKeyValue("data.rpt_token", keyValue, BUF_SIZE) == RET_SUCCESS)
			Set_Ox_Storage(s_cfg->client_name, "uma.rpt_token", keyValue, 0);
		else
			return -1;
	}
	else
	{
		return -1;
	}

	return 0;
}

/*
* Register permission ticket
* http://ox.gluu.org/doku.php?id=oxd:communication_protocol#register_permission_ticket
*/
int ox_register_ticket(mod_ox_config *s_cfg)
{
#define BUF_SIZE 8192
	char responseStr[BUF_SIZE];
	char keyValue[BUF_SIZE];
	int ret;
	int responseLen;
	char tmp[5];
	int i;

	char *pat_token = Get_Ox_Storage(s_cfg->client_name, "uma.pat_token");
	std::string id = std::string(s_cfg->uma_resource_name);
	id += "_id";
	char *resource_set_id = Get_Ox_Storage(s_cfg->client_name, id.c_str());

	if ((s_cfg->uma_am_host[0].host == NULL) || (s_cfg->uma_am_host[0].scope[0] == NULL))
		return -1;

	for (i=0; i<5; i++)
	{
		if (s_cfg->uma_am_host[0].scope[i] == NULL)
			break;
	}
	if (i == 0) return -1;

	const char *res_scope[] = {
		s_cfg->uma_am_host[0].scope[0], 
		s_cfg->uma_am_host[0].scope[1], 
		s_cfg->uma_am_host[0].scope[2], 
		s_cfg->uma_am_host[0].scope[3], 
		s_cfg->uma_am_host[0].scope[4]
	};

	ret = oxd_register_ticket(s_cfg->oxd_hostaddr, s_cfg->oxd_portnum, s_cfg->uma_discovery_url, pat_token, \
		s_cfg->uma_am_host[0].host, s_cfg->uma_rs_host, i, res_scope, resource_set_id, responseStr);

	if (pat_token) free(pat_token);
	if (resource_set_id) free(resource_set_id);

	if (ret == RET_FAILURE)
		return -1;

	memcpy(tmp, responseStr, 4); tmp[4] = 0;
	responseLen = atoi(tmp);
	if (libjson_init(&responseStr[4], responseLen) == RET_SUCCESS)
	{
		if (libjson_getKeyValue("status", keyValue, BUF_SIZE) == RET_SUCCESS)
		{
			if (strcmp(keyValue, "ok"))
				return -1;
		}
		else
		{
			return -1;
		}

		if (libjson_getKeyValue("data.ticket", keyValue, BUF_SIZE) == RET_SUCCESS)
		{
			std::string resource_ticket = std::string(s_cfg->uma_resource_name);
			resource_ticket += "_ticket";
			Set_Ox_Storage(s_cfg->client_name, resource_ticket.c_str(), keyValue, 0);

			return 0;
		}
		else
		{
			return -1;
		}
	}
	else
	{
		return -1;
	}

	return -1;
}

/*
* Authorize RPT
* http://ox.gluu.org/doku.php?id=oxd:communication_protocol#authorize_rpt
*/
int ox_authorize_rpt(mod_ox_config *s_cfg, const char *session_id)
{
#define BUF_SIZE 8192
	char responseStr[BUF_SIZE];
	char keyValue[BUF_SIZE];
	int ret;
	int responseLen;
	char tmp[5];

	char *aat_token = Get_Ox_Storage(s_cfg->client_name, "uma.aat_token");
	char *rpt_token = Get_Ox_Storage(s_cfg->client_name, "uma.rpt_token");
	std::string resource_ticket = std::string(s_cfg->uma_resource_name);
	resource_ticket += "_ticket";
	char *ticket = Get_Ox_Storage(s_cfg->client_name, resource_ticket.c_str());

	std::string claim_list = "";
	if(session_id != NULL) 
	{
		// Make Claim string
		{
			char *token[MAX_ATTR_NUM];
			char uma_claims_str[1024];
			int i = 0;
			std::string attr_name;

			for (i=0; i<MAX_ATTR_NUM; i++)
				token[i] = NULL;

			strcpy(uma_claims_str, s_cfg->uma_sent_user_claims);
			i = 0;
			token[i] = strtok(uma_claims_str, "+");
			while(token[i]!= NULL) 
			{
				i++; if (i >= MAX_ATTR_NUM) break;		
				token[i] = strtok(NULL, "+");
			}

			i = 0;
			while(token[i]!= NULL) {
				attr_name = session_id;
				attr_name += ".";
				attr_name += token[i];

				char *claim = NULL;
				claim = Get_Ox_Storage(NULL, attr_name.c_str());
				if (claim != NULL)
				{
					if (claim_list != "")
						claim_list += ",";
					claim_list += "\"";
					claim_list += token[i];
					claim_list += "\"";
					claim_list += ":";
					claim_list += "[\"";
					claim_list += claim;
					claim_list += "\"]";
					free(claim);
				}
				i++; if (i >= MAX_ATTR_NUM) break;		
			}
		}
	}
	else
		return -1;

	ret = oxd_authorize_rpt_token(s_cfg->oxd_hostaddr, s_cfg->oxd_portnum, aat_token, \
		rpt_token, s_cfg->uma_am_host[0].host, ticket, claim_list.c_str(), responseStr);

	if (aat_token) free(aat_token);
	if (rpt_token) free(rpt_token);
	if (ticket) free(ticket);

	if (ret == RET_FAILURE)
		return -1;

	memcpy(tmp, responseStr, 4); tmp[4] = 0;
	responseLen = atoi(tmp);
	if (libjson_init(&responseStr[4], responseLen) == RET_SUCCESS)
	{
		if (libjson_getKeyValue("status", keyValue, BUF_SIZE) == RET_SUCCESS)
		{
			if (strcmp(keyValue, "ok"))
				return -1;
		}
		else
		{
			return -1;
		}
	}
	else
	{
		return -1;
	}

	return 0;
}

/*
* Check status of RPT
* http://ox.gluu.org/doku.php?id=oxd:communication_protocol#check_status_of_rpt
*/
int ox_check_rpt_status(mod_ox_config *s_cfg)
{
#define BUF_SIZE 8192
	char responseStr[BUF_SIZE];
	char keyValue[BUF_SIZE];
	int ret;
	int responseLen;
	char tmp[5];

	char *pat_token = Get_Ox_Storage(s_cfg->client_name, "uma.pat_token");
	char *rpt_token = Get_Ox_Storage(s_cfg->client_name, "uma.rpt_token");

	ret = oxd_check_rpt_status(s_cfg->oxd_hostaddr, s_cfg->oxd_portnum, s_cfg->uma_discovery_url, pat_token, rpt_token, responseStr);

	if (pat_token) free(pat_token);
	if (rpt_token) free(rpt_token);

	if (ret == RET_FAILURE)
		return -1;

	memcpy(tmp, responseStr, 4); tmp[4] = 0;
	responseLen = atoi(tmp);
	if (libjson_init(&responseStr[4], responseLen) == RET_SUCCESS)
	{
		if (libjson_getKeyValue("status", keyValue, BUF_SIZE) == RET_SUCCESS)
		{
			if (strcmp(keyValue, "ok"))
				return -1;
		}
		else
		{
			return -1;
		}

		bool keyBoolValue=false;
		if (libjson_getKeyValue("data.active", &keyBoolValue) == RET_SUCCESS)
		{
			if (keyBoolValue != true)
				return -1;
		}
		else
		{
			double keyIntValue = 0;
			if (libjson_getKeyValue("data.expires_at", &keyIntValue) == RET_SUCCESS)
			{
				time_t rawtime;
				time (&rawtime);
				if (rawtime < (time_t)keyIntValue)
					return -1;
				else
					return 0;
			}
			else
			{
				return -1;
			}
		}
	}
	else
	{
		return -1;
	}

	return 0;
}
