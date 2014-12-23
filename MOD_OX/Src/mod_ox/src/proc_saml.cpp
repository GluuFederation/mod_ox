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
#include "proc_saml.h"
#include "oxd_main.h"

/*
* check oxd discovery infos in memcached.
* true : unchanged, false : changed
*/
static bool check_discovery_infos(mod_ox_config *s_cfg)
{
	bool ret = true;

	char *oxdhost = Get_Ox_Storage(s_cfg->OpenIDClientName, "oxd.oxdhost");
	char *discovery = Get_Ox_Storage(s_cfg->OpenIDClientName, "connect.discovery");
	char *redirect = Get_Ox_Storage(s_cfg->OpenIDClientName, "connect.redirect");
	char *clientname = Get_Ox_Storage(s_cfg->OpenIDClientName, "oxd.clientname");
	char *creditpath = Get_Ox_Storage(s_cfg->OpenIDClientName, "oxd.creditpath");
	char *uma_discovery = Get_Ox_Storage(s_cfg->OpenIDClientName, "uma.discovery");
	char *uma_resource = Get_Ox_Storage(s_cfg->OpenIDClientName, "uma.resource");
	char *uma_rshost = Get_Ox_Storage(s_cfg->OpenIDClientName, "uma.rshost");

	if (!oxdhost || !discovery || !redirect || !clientname || !uma_discovery || !uma_resource || !uma_rshost || (!creditpath && s_cfg->ClientCredsPath))
	{
		Set_Ox_Storage(s_cfg->OpenIDClientName, "oxd.oxdhost", s_cfg->OxdHostAddr, 0);
		Set_Ox_Storage(s_cfg->OpenIDClientName, "connect.discovery", s_cfg->OpenIDProvider, 0);
		Set_Ox_Storage(s_cfg->OpenIDClientName, "connect.redirect", s_cfg->login_url, 0);
		Set_Ox_Storage(s_cfg->OpenIDClientName, "oxd.clientname", s_cfg->OpenIDClientName, 0);
		Set_Ox_Storage(s_cfg->OpenIDClientName, "oxd.creditpath", s_cfg->ClientCredsPath, 0);
		Set_Ox_Storage(s_cfg->OpenIDClientName, "uma.discovery", s_cfg->UmaAuthorizationServer, 0);
		Set_Ox_Storage(s_cfg->OpenIDClientName, "uma.resource", s_cfg->UmaResourceName, 0);
		Set_Ox_Storage(s_cfg->OpenIDClientName, "uma.rshost", s_cfg->uma_rs_host, 0);

		ret = false; 
		goto EXIT_check_discovery_infos;
	}

	if (strcmp(oxdhost, s_cfg->OxdHostAddr) ||
		strcmp(discovery, s_cfg->OpenIDProvider) ||
		strcmp(redirect, s_cfg->login_url) ||
		strcmp(clientname, s_cfg->OpenIDClientName) ||
		strcmp(uma_discovery, s_cfg->UmaAuthorizationServer) ||
		strcmp(uma_resource, s_cfg->UmaResourceName) ||
		strcmp(uma_rshost, s_cfg->uma_rs_host) || 
		(s_cfg->ClientCredsPath && strcmp(creditpath, s_cfg->ClientCredsPath)))
	{
		Set_Ox_Storage(s_cfg->OpenIDClientName, "oxd.oxdhost", s_cfg->OxdHostAddr, 0);
		Set_Ox_Storage(s_cfg->OpenIDClientName, "connect.discovery", s_cfg->OpenIDProvider, 0);
		Set_Ox_Storage(s_cfg->OpenIDClientName, "connect.redirect", s_cfg->login_url, 0);
		Set_Ox_Storage(s_cfg->OpenIDClientName, "oxd.clientname", s_cfg->OpenIDClientName, 0);
		Set_Ox_Storage(s_cfg->OpenIDClientName, "oxd.creditpath", s_cfg->ClientCredsPath, 0);
		Set_Ox_Storage(s_cfg->OpenIDClientName, "uma.discovery", s_cfg->UmaAuthorizationServer, 0);
		Set_Ox_Storage(s_cfg->OpenIDClientName, "uma.resource", s_cfg->UmaResourceName, 0);
		Set_Ox_Storage(s_cfg->OpenIDClientName, "uma.rshost", s_cfg->uma_rs_host, 0);

		ret = false;
		goto EXIT_check_discovery_infos;
	}

EXIT_check_discovery_infos:
	if (oxdhost) free(oxdhost);
	if (discovery) free(discovery);
	if (redirect) free(redirect);
	if (clientname) free(clientname);
	if (creditpath) free(creditpath);
	if (uma_discovery) free(uma_discovery);
	if (uma_resource) free(uma_resource);
	if (uma_rshost) free(uma_rshost);

	return ret;
};

static void set_rpt_cookie(request_rec *r, mod_ox_config *s_cfg, opkele::params_t& params)
{
	// now set auth cookie, if we're doing session based auth
	std::string session_id, hostname, path, cookie_value, state, redirect_location, args;
	int expires_in;
	if(s_cfg->CookiePath != NULL) 
		path = std::string(s_cfg->CookiePath); 
	else 
		modox::base_dir(std::string(r->uri), path);

	modox::make_rstring(32, session_id);
	expires_in = 0;

	modox::make_cookie_value(cookie_value, std::string(s_cfg->cookie_name), session_id, path, expires_in, false); 
	apr_table_set(r->err_headers_out, "Set-Cookie", cookie_value.c_str());
	hostname = std::string(r->hostname);

	// save session values
	std::string session_str = session_id + ";";
	session_str += hostname + ";";
	session_str += path + ";";
	session_str += "identity;";
	session_str += "username";
	Set_Ox_Storage(s_cfg->OpenIDClientName, session_id.c_str(), session_str.c_str(), expires_in);

	r->args = NULL;

	return;
};

/*
* save session value after succeed in authorize.
*/
static void set_valid_session(request_rec *r, mod_ox_config *s_cfg) {
	// test for valid session
	std::string session_id = "";
	std::string session_key = "";	
	std::string session_value = "";
	modox::get_session_id(r, std::string(s_cfg->cookie_name), session_key, session_id);
	modox::get_session_id(r, "_shibsession_", session_key, session_value);

	if(session_id != "" && session_key != "" && session_value != "") 
	{
		std::string session_cookie = session_value;
		session_cookie += ".cookie";

		Set_Ox_Storage(s_cfg->OpenIDClientName, session_cookie.c_str(), session_key.c_str(), 0);
	}
};

/*
* start the process for authentication.
*/
int start_saml_session(request_rec *r, mod_ox_config *s_cfg, opkele::params_t& params) 
{
	int ret;
	bool info_changed = false;

	modox::remove_openid_vars(params);

	ret = 0;
	if (check_discovery_infos(s_cfg) == true)	// unchanged
	{
		// Discovery & Register Client
		char *issuer = Get_Ox_Storage(s_cfg->OpenIDClientName, "oxd.issuer");
		char *authorization_endpoint = Get_Ox_Storage(s_cfg->OpenIDClientName, "oxd.authorization_endpoint");
		char *client_id = Get_Ox_Storage(s_cfg->OpenIDClientName, "oxd.client_id");
		char *client_secret = Get_Ox_Storage(s_cfg->OpenIDClientName, "oxd.client_secret");
		if ((issuer==NULL) || (authorization_endpoint==NULL) || (client_id==NULL) || (client_secret==NULL))
		{
			info_changed = true;
			ret = ox_discovery(s_cfg);
		}
		if (issuer) free(issuer);
		if (authorization_endpoint) free(authorization_endpoint);
		if (client_id) free(client_id);
		if (client_secret) free(client_secret);
		if (ret < 0) return show_error(r, s_cfg, "Oxd failed to discovery");

		// Obtain PAT & Register Resource
		char *pat_token = Get_Ox_Storage(s_cfg->OpenIDClientName, "uma.pat_token");
		if (pat_token==NULL)
		{
			if (ox_obtain_pat(s_cfg) < 0) return show_error(r, s_cfg, "Oxd failed to obtain PAT");
			if (ox_register_resources(s_cfg) < 0) return show_error(r, s_cfg, "Oxd failed to register Resource");
		}
		else
		{
			free(pat_token);

			std::string id = std::string(s_cfg->UmaResourceName); id += "_id";
			std::string rev = std::string(s_cfg->UmaResourceName); rev += "_rev";
			char *resource_id = Get_Ox_Storage(s_cfg->OpenIDClientName, id.c_str());
			char *resource_rev = Get_Ox_Storage(s_cfg->OpenIDClientName, rev.c_str());
			
			if (!resource_id || !resource_rev)
				ret = ox_register_resources(s_cfg);

			if (resource_id) free(resource_id);
			if (resource_rev) free(resource_rev);
			if (ret < 0) return show_error(r, s_cfg, "Oxd failed to register Resource");
		}

		// Obtain AAT Token
		char *aat_token = Get_Ox_Storage(s_cfg->OpenIDClientName, "uma.aat_token");
		if ((aat_token==NULL))
		{
			if (ox_obtain_aat(s_cfg) < 0) return show_error(r, s_cfg, "Oxd failed to obtain AAT");
		}
		else
			free(aat_token);

		// 5. Obtain RPT Token
		char *rpt_token = Get_Ox_Storage(s_cfg->OpenIDClientName, "uma.rpt_token");
		if ((rpt_token==NULL))
		{
			if (ox_obtain_rpt(s_cfg) < 0) return show_error(r, s_cfg, "Oxd failed to obtain RPT");
		}
		else
			free(rpt_token);
	} 
	else	// changed
	{
		info_changed = true;
		// Discovery & Register Client
		if (ox_discovery(s_cfg) < 0) return show_error(r, s_cfg, "Oxd failed to discovery");
		// Obtain PAT
		if (ox_obtain_pat(s_cfg) < 0) return show_error(r, s_cfg, "Oxd failed to obtain PAT");
		// Register Resource
		if (ox_register_resources(s_cfg) < 0) return show_error(r, s_cfg, "Oxd failed to register Resource");
		// Obtain AAT
		if (ox_obtain_aat(s_cfg) < 0) return show_error(r, s_cfg, "Oxd failed to obtain AAT");
		// Obtain RPT
		if (ox_obtain_rpt(s_cfg) < 0) return show_error(r, s_cfg, "Oxd failed to obtain RPT");
	}

	set_rpt_cookie(r, s_cfg, params);

	params["target"] = "https://"; 
	params["target"] += r->hostname; 
	params["target"] += r->uri;
	params["path"] = std::string(r->uri);
	params["attrs"] = std::string(s_cfg->uma_sent_user_claims);
	std::string auth_end;
	auth_end = std::string(s_cfg->SAMLRedirectUrl);

	return modox::http_redirect(r, params.append_query(auth_end, "")); 
};

/*
* check to has session for shibd
*/
int has_saml_session(request_rec *r, mod_ox_config *s_cfg, opkele::params_t& params)
{
	// test for valid session
	std::string session_id = "";
	std::string session_key = "";	
	std::string session_value = "";
	modox::get_session_id(r, std::string(s_cfg->cookie_name), session_key, session_id);
	modox::get_session_id(r, "_shibsession_", session_key, session_value);

	if(session_id != "" && session_key != "" && session_value != "") 
	{
		modox::debug("found session_id in cookie: " + session_id);

		// Check valid session is saved
		std::string session_cookie = session_value;
		session_cookie += ".cookie";

		char *cookie_str = Get_Ox_Storage(s_cfg->OpenIDClientName, session_cookie.c_str());
		if (cookie_str != NULL)
		{
			if (!strcmp(cookie_str, session_key.c_str()))
			{
				free(cookie_str);
				return 1;
			}
			free(cookie_str);
		}

		// Check session value
		modox::session_t session;

		char *session_str = Get_Ox_Storage(s_cfg->OpenIDClientName, session_id.c_str());
		char *ptr6, *ptr7, *ptr8, *ptr9, *ptr10;
		ptr6 = strtok(session_str, ";");
		ptr7 = strtok(NULL, ";");
		ptr8 = strtok(NULL, ";");
		ptr9 = strtok(NULL, ";");
		ptr10 = strtok(NULL, ";");

		session.session_id = std::string(ptr6);
		session.hostname = std::string(ptr7);
		session.path = std::string(ptr8);
		session.identity = std::string(ptr9);
		session.username = std::string(ptr10);

		// if session found 
		if(session.identity != "") 
		{
			std::string uri_path;
			modox::base_dir(std::string(r->uri), uri_path);
			std::string valid_path(session.path);
			// if found session has a valid path
			if(valid_path == uri_path.substr(0, valid_path.size()) && strcmp(session.hostname.c_str(), r->hostname)==0) 
			{
				const char* idchar = session.identity.c_str();
				r->user = apr_pstrdup(r->pool, idchar);

				if (session_str) free(session_str);
				return 0;
			} 
		}

		if (session_str) free(session_str);
	}

	return -1;
};

/*
* check the validation of session
*/
int validate_saml_session(request_rec *r, mod_ox_config *s_cfg, opkele::params_t& params) 
{
	if (ox_obtain_rpt(s_cfg) < 0)
		return HTTP_FORBIDDEN;

	if (ox_register_ticket(s_cfg) < 0)
		return HTTP_FORBIDDEN;

	// test for valid session
	std::string session_id = "";
	std::string session_key = "";	
	std::string session_value = "";
	modox::get_session_id(r, std::string(s_cfg->cookie_name), session_key, session_id);
	modox::get_session_id(r, "_shibsession_", session_key, session_value);
	if (session_value != "")
	{
		if (ox_authorize_rpt(s_cfg, session_value.c_str()) < 0)
			return HTTP_FORBIDDEN;
	}
	
	if (ox_check_rpt_status(s_cfg) < 0)
		return HTTP_FORBIDDEN;

	set_valid_session(r, s_cfg);

	return 0;
};