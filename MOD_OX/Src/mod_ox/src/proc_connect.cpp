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
#include "opk_util.h"
#include "proc_connect.h"
#include "oxd_main.h"

/**
* Returns true if the current request in the connection has an
* "X-Forwarded-Proto: https" header from a trusted BIG IP proxy.
* This emulates the ssl_is_https(conn_rec *) function in mod_ssl
* and is used to populate the %{HTTPS} variable in mod_rewrite,
* for example.
*/
static int ssl_is_https(conn_rec *c) {
	const char *https;
	https = apr_table_get(c->notes, BIGIP_HTTPS_NOTE);
	return (https) && (0 == strcmp(https, BIGIP_HTTPS_ON));
}

// Get the full URI of the request_rec's request location 
// clean_params specifies whether or not all openid.* and modoic.* params should be cleared
static void full_uri(request_rec *r, std::string& result, mod_ox_config *s_cfg, char *return_uri=NULL, bool clean_params=false) {
	std::string hostname(r->hostname);
	std::string uri = (return_uri)?std::string(return_uri):std::string(r->uri);
	apr_port_t i_port = ap_get_server_port(r);
	// Fetch the APR function for determining if we are looking at an https URL
	std::string prefix = ssl_is_https(r->connection) ? "https://" : "http://";
	char *port = apr_psprintf(r->pool, "%lu", (unsigned long) i_port);
	std::string s_port = (i_port == 80 || i_port == 443) ? "" : ":" + std::string(port);

	std::string args;
	if(clean_params) {
		opkele::params_t params;
		if(r->args != NULL) params = modox::parse_query_string(std::string(r->args));
		modox::remove_openid_vars(params);
		args = params.append_query("", "");
	} else {
		args = (r->args == NULL) ? "" : "?" + std::string(r->args);
	}

	result = prefix + hostname + s_port + uri + args;
}

/*
* check oxd discovery infos in memcached.
* true : unchanged, false : changed
*/
static bool check_discovery_infos(mod_ox_config *s_cfg)
{
	bool ret = true;

	char *oxdhost = Get_Ox_Storage(s_cfg->client_name, "oxd.oxdhost");
	char *discovery = Get_Ox_Storage(s_cfg->client_name, "connect.discovery");
	char *redirect = Get_Ox_Storage(s_cfg->client_name, "connect.redirect");
	char *clientname = Get_Ox_Storage(s_cfg->client_name, "oxd.clientname");
	char *creditpath = Get_Ox_Storage(s_cfg->client_name, "oxd.creditpath");

	if (!oxdhost || !discovery || !redirect || !clientname || (!creditpath && s_cfg->credit_path))
	{
		Set_Ox_Storage(s_cfg->client_name, "oxd.oxdhost", s_cfg->oxd_hostaddr, 0);
		Set_Ox_Storage(s_cfg->client_name, "connect.discovery", s_cfg->discovery_url, 0);
		Set_Ox_Storage(s_cfg->client_name, "connect.redirect", s_cfg->login_url, 0);
		Set_Ox_Storage(s_cfg->client_name, "oxd.clientname", s_cfg->client_name, 0);
		Set_Ox_Storage(s_cfg->client_name, "oxd.creditpath", s_cfg->credit_path, 0);

		ret = false; 
		goto EXIT_check_discovery_infos;
	}

	if (strcmp(oxdhost, s_cfg->oxd_hostaddr) ||
		strcmp(discovery, s_cfg->discovery_url) ||
		strcmp(redirect, s_cfg->login_url) ||
		strcmp(clientname, s_cfg->client_name) || 
		(s_cfg->credit_path && strcmp(creditpath, s_cfg->credit_path)))
	{
		Set_Ox_Storage(s_cfg->client_name, "oxd.oxdhost", s_cfg->oxd_hostaddr, 0);
		Set_Ox_Storage(s_cfg->client_name, "connect.discovery", s_cfg->discovery_url, 0);
		Set_Ox_Storage(s_cfg->client_name, "connect.redirect", s_cfg->login_url, 0);
		Set_Ox_Storage(s_cfg->client_name, "oxd.clientname", s_cfg->client_name, 0);
		Set_Ox_Storage(s_cfg->client_name, "oxd.creditpath", s_cfg->credit_path, 0);

		ret = false;
		goto EXIT_check_discovery_infos;
	}

EXIT_check_discovery_infos:
	if (oxdhost) free(oxdhost);
	if (discovery) free(discovery);
	if (redirect) free(redirect);
	if (clientname) free(clientname);
	if (creditpath) free(creditpath);

	return ret;
};

static int set_connect_cookie(request_rec *r, mod_ox_config *s_cfg, opkele::params_t& params, std::string &session_id, int token_timeout)
 {
	// now set auth cookie, if we're doing session based auth
	std::string hostname, path, cookie_value, id_token, access_token, scope, state, redirect_location, args;
	int expires_in;

	if(s_cfg->cookie_path != NULL) 
		path = std::string(s_cfg->cookie_path); 
	else 
		modox::base_dir(std::string(r->unparsed_uri), path);

	if (params.has_param("state"))
		state = params.get_param("state");
	else
		return show_error(r, s_cfg, "unauthorized");

	if (params.has_param("expires_in"))
	{
		std::string expire_str = params.get_param("expires_in");
		expires_in = atoi(expire_str.c_str());
	} 
	else
	{
		expires_in = token_timeout;
	}

	modox::make_cookie_value(cookie_value, std::string(s_cfg->cookie_name), session_id, path, expires_in, false); 
	apr_table_set(r->err_headers_out, "Set-Cookie", cookie_value.c_str());
	hostname = std::string(r->hostname);

	// save session values
	std::string session_str = session_id + ";";
	session_str += hostname + ";";
	session_str += path + ";";
	session_str += "identity;";
	session_str += "username";
	Set_Ox_Storage(s_cfg->client_name, session_id.c_str(), session_str.c_str(), expires_in);

	char *return_uri = Get_Ox_Storage(s_cfg->client_name, state.c_str());
	if (return_uri == NULL)
		return show_error(r, s_cfg, "Incorrect Return URI");

	r->args = NULL;

	redirect_location = return_uri;
	if (return_uri) free(return_uri);
	return modox::http_redirect(r, redirect_location);
};

/*
* start the process for authentication.
*/
static int oic_check_session(mod_ox_config *s_cfg, const char *id_token, const char *session_id)
{
	return ox_check_id_token(s_cfg, id_token, session_id);
}

/*
* start the process for authentication.
*/
int start_connect_session(request_rec *r, mod_ox_config *s_cfg, opkele::params_t& params) 
{
	int ret;
	bool info_changed = false;
	const apr_array_header_t    *fields;
	int                         i;
	apr_table_entry_t           *e = 0;

	modox::remove_openid_vars(params);

	ret = 0;
	if (check_discovery_infos(s_cfg) == true)	// unchanged
	{
		// Discovery & Register Client
		char *issuer = Get_Ox_Storage(s_cfg->client_name, "oxd.issuer");
		char *authorization_endpoint = Get_Ox_Storage(s_cfg->client_name, "oxd.authorization_endpoint");
		char *token_endpoint = Get_Ox_Storage(s_cfg->client_name, "oxd.token_endpoint");
		char *client_id = Get_Ox_Storage(s_cfg->client_name, "oxd.client_id");
		char *client_secret = Get_Ox_Storage(s_cfg->client_name, "oxd.client_secret");
		if ((issuer==NULL) || (authorization_endpoint==NULL) || (client_id==NULL) || (client_secret==NULL))
		{
			info_changed = true;
			ret = ox_discovery(s_cfg);
		}
		if (issuer) free(issuer);
		if (authorization_endpoint) free(authorization_endpoint);
		if (token_endpoint) free(token_endpoint);
		if (client_id) free(client_id);
		if (client_secret) free(client_secret);
		if (ret < 0) return show_error(r, s_cfg, "Oxd failed to discovery");
	} 
	else	// changed
	{
		info_changed = true;
		// Discovery & Register Client
		if (ox_discovery(s_cfg) < 0) return show_error(r, s_cfg, "Oxd failed to discovery");
	}

	char *issuer = Get_Ox_Storage(s_cfg->client_name, "oxd.issuer");
	char *authorization_endpoint = Get_Ox_Storage(s_cfg->client_name, "oxd.authorization_endpoint");
	char *client_id = Get_Ox_Storage(s_cfg->client_name, "oxd.client_id");

	if ((issuer==NULL) || (authorization_endpoint==NULL) || (client_id==NULL))
	{
		if (issuer) free(issuer);
		if (authorization_endpoint) free(authorization_endpoint);
		if (client_id) free(client_id);

		return show_error(r, s_cfg, "Oxd failed to discovery");
	}

	std::string identity = std::string(issuer);
	APDEBUG(r, "identity = %s", issuer);

	// add a nonce and reset what return_to is
	std::string nonce;
	modox::make_rstring(10, nonce);
	params["nonce"] = nonce;

	std::string state;
	modox::make_rstring(10, state);
	params["state"] = state;
	if(params.has_param("target")) 
	{
		Set_Ox_Storage(s_cfg->client_name, state.c_str(), params.get_param("target").c_str(), 0);
	}
	else
	{
		std::string target_location;
		if (s_cfg->destination_url)
		{
			Set_Ox_Storage(s_cfg->client_name, state.c_str(), s_cfg->destination_url, 0);
		} 
		else
		{
			full_uri(r, target_location, s_cfg, r->uri);
			Set_Ox_Storage(s_cfg->client_name, state.c_str(), target_location.c_str(), 0);
		}
	}

	// build Redirect parameters
	std::string origin_headers = "{";
	// send headers
	if (s_cfg->send_headers == TRUE)
	{
		fields = apr_table_elts(r->headers_in);
		e = (apr_table_entry_t *) fields->elts;
		if (fields->nelts > 0)
		{
			for(i = 0; i < (fields->nelts-1); i++) {
				origin_headers += "\"";
				origin_headers += e[i].key;
				origin_headers += "\":\"";
				origin_headers += e[i].val;
				origin_headers += "\",";
			}
			origin_headers += "\"";
			origin_headers += e[i].key;
			origin_headers += "\":\"";
			origin_headers += e[i].val;
			origin_headers += "\"}";
			params["origin_headers"] = origin_headers;
		}
	}

	if (client_id) params["client_id"] = client_id;
	if (s_cfg->response_type) params["response_type"] = s_cfg->response_type;
	params["scope"] = "openid profile address email";

	std::string redirect_uri = s_cfg->login_url;
	redirect_uri += "redirect";
	params["redirect_uri"] = redirect_uri;

	std::string requested_acr = "[\"";
	requested_acr += s_cfg->requested_acr;
	requested_acr += "\"]";
	if (s_cfg->requested_acr) params["acr_values"] = requested_acr;
	
	std::string auth_end = std::string(authorization_endpoint);

	if (issuer) free(issuer);
	if (authorization_endpoint) free(authorization_endpoint);
	if (client_id) free(client_id);

	// Redirect to seed.gluu.org
	return modox::http_redirect(r, params.append_query(auth_end, ""));
};

/*
* send request to Token Endpoint.
*/
int send_request_token(request_rec *r, mod_ox_config *s_cfg, opkele::params_t& params) 
{
	int ret;
	bool info_changed = false;
	const apr_array_header_t    *fields;
	int                         i;
	apr_table_entry_t           *e = 0;

	ret = 0;
	if (check_discovery_infos(s_cfg) == true)	// unchanged
	{
		// Discovery & Register Client
		char *issuer = Get_Ox_Storage(s_cfg->client_name, "oxd.issuer");
		char *authorization_endpoint = Get_Ox_Storage(s_cfg->client_name, "oxd.authorization_endpoint");
		char *token_endpoint = Get_Ox_Storage(s_cfg->client_name, "oxd.token_endpoint");
		char *client_id = Get_Ox_Storage(s_cfg->client_name, "oxd.client_id");
		char *client_secret = Get_Ox_Storage(s_cfg->client_name, "oxd.client_secret");
		if ((issuer==NULL) || (authorization_endpoint==NULL) || (client_id==NULL) || (client_secret==NULL))
		{
			info_changed = true;
			ret = ox_discovery(s_cfg);
		}
		if (issuer) free(issuer);
		if (authorization_endpoint) free(authorization_endpoint);
		if (token_endpoint) free(token_endpoint);
		if (client_id) free(client_id);
		if (client_secret) free(client_secret);
		if (ret < 0) return show_error(r, s_cfg, "Oxd failed to discovery");
	} 
	else	// changed
	{
		info_changed = true;
		// Discovery & Register Client
		if (ox_discovery(s_cfg) < 0) return show_error(r, s_cfg, "Oxd failed to discovery");
	}

	char *token_endpoint = Get_Ox_Storage(s_cfg->client_name, "oxd.token_endpoint");

	if (token_endpoint==NULL)
	{
		return show_error(r, s_cfg, "Oxd failed to discovery");
	}

	// build Redirect parameters
	std::string origin_headers = "{";
	// send headers
	if (s_cfg->send_headers == TRUE)
	{
		fields = apr_table_elts(r->headers_in);
		e = (apr_table_entry_t *) fields->elts;
		if (fields->nelts > 0)
		{
			for(i = 0; i < (fields->nelts-1); i++) {
				origin_headers += "\"";
				origin_headers += e[i].key;
				origin_headers += "\":\"";
				origin_headers += e[i].val;
				origin_headers += "\",";
			}
			origin_headers += "\"";
			origin_headers += e[i].key;
			origin_headers += "\":\"";
			origin_headers += e[i].val;
			origin_headers += "\"}";
			params["origin_headers"] = origin_headers;
		}
	}

	params["grant_type"] = "authorization_code";
	// Get code from params
	std::string code;
	if (params.has_param("code"))
		code = params.get_param("code");
	else
		return show_error(r, s_cfg, "unauthorized");
	params["code"] = code;

	std::string redirect_uri = s_cfg->login_url;
	redirect_uri += "redirect";
	params["redirect_uri"] = redirect_uri;

	std::string auth_end = std::string(token_endpoint);

	if (token_endpoint) free(token_endpoint);

	// Redirect to seed.gluu.org
	return modox::http_redirect(r, params.append_query(auth_end, ""));
};

/*
* check to has session for oic
*/
int has_connect_session(request_rec *r, mod_ox_config *s_cfg, opkele::params_t& params, int log_out)
{
	// test for valid session
	std::string session_id = "";
	std::string session_value = "";
	if (s_cfg->cookie_name != NULL)
		modox::get_session_id(r, std::string(s_cfg->cookie_name), session_id, session_value);
	if(session_id != "")
	{ // Found Session ID
		modox::debug("found session_id in cookie: " + session_id);
		modox::session_t session;

		// Get Session String
		char *session_str = Get_Ox_Storage(s_cfg->client_name, session_value.c_str());
		if (!session_str)
			goto EXIT_has_connect_session;

		if (log_out)
		{
			char id_token[1024] = "";
			modox::debug("deleting session: " + session_id);

			char *id_token_str = Get_Ox_Storage(session_value.c_str(), "id_token");
			if (id_token_str != NULL)
				strcpy(id_token, id_token_str);
			free(id_token_str);
			Remove_Ox_Storage(s_cfg->client_name, session_value.c_str());
			apr_table_clear(r->subprocess_env);
			Remove_Ox_Storage(session_value.c_str(), "session_id");
			Remove_Ox_Storage(session_value.c_str(), "id_token");
			Remove_Ox_Storage(session_value.c_str(), "access_token");
			Remove_Ox_Storage(session_value.c_str(), "scope");
			Remove_Ox_Storage(session_value.c_str(), "state");
			Remove_Ox_Storage(s_cfg->client_name, session_id.c_str());

			if (session_str) free(session_str);

			params.clear();
			if (s_cfg->postlogout_url)
			{
				params["id_token_hint"] = id_token;
				if (s_cfg->logoutredirect_url != NULL)
					params["post_logout_redirect_uri"] = s_cfg->logoutredirect_url;
				else
					params["post_logout_redirect_uri"] = "";
				std::string redirect_end = std::string(s_cfg->postlogout_url);
				return modox::http_redirect(r, params.append_query(redirect_end, ""));
			}

			return -1;
		}

		char *ptr6, *ptr7, *ptr8, *ptr9, *ptr10;
		ptr6 = strtok(session_str, ";");
		ptr7 = strtok(NULL, ";");
		ptr8 = strtok(NULL, ";");
		ptr9 = strtok(NULL, ";");
		ptr10 = strtok(NULL, ";");
		if (!ptr6 || !ptr7 || !ptr8 || !ptr9 || !ptr10)
		{
			free(session_str);
			goto EXIT_has_connect_session;
		}

		session.session_id = std::string(ptr6);
		session.hostname = std::string(ptr7);
		session.path = std::string(ptr8);
		session.identity = std::string(ptr9);
		session.username = std::string(ptr10);

		// if session found 
		if(session.identity != "") 
		{
			std::string uri_path(r->uri);
			//modox::base_dir(std::string(r->uri), uri_path);
			std::string valid_path(session.path);
			// if found session has a valid path
			if((valid_path==uri_path.substr(0, valid_path.size()) ||
				(((uri_path.size()+1)==valid_path.size())) && (strncasecmp(uri_path.c_str(), valid_path.c_str(), uri_path.size()) == 0))
				&& strcasecmp(session.hostname.c_str(), r->hostname)==0) 
			{
				const char* idchar = session.identity.c_str();
				r->user = apr_pstrdup(r->pool, idchar);
				if (session_str) free(session_str);

				// set environment variable
				// SESSION_ID
				char *session_id_str = Get_Ox_Storage(session_value.c_str(), "session_id");
				if (session_id_str)
				{
					apr_table_set(r->subprocess_env, "OIC_SESSION_ID", session_id_str);
					apr_table_set(r->headers_in, "OIC_SESSION_ID", session_id_str);
					apr_table_set(r->err_headers_out, "OIC_SESSION_ID", session_id_str);
					free(session_id_str);
				}

				// ID_TOKEN
				char *id_token_str = Get_Ox_Storage(session_value.c_str(), "id_token");
				if (id_token_str)
				{
					apr_table_set(r->subprocess_env, "OIC_ID_TOKEN", id_token_str);
					apr_table_set(r->headers_in, "OIC_ID_TOKEN", id_token_str);
					apr_table_set(r->err_headers_out, "OIC_ID_TOKEN", id_token_str);
					free(id_token_str);
				}

				// ACCESS TOKEN
				char *access_token_str = Get_Ox_Storage(session_value.c_str(), "access_token");
				if (access_token_str)
				{
					apr_table_set(r->subprocess_env, "OIC_ACCESS_TOKEN", access_token_str);
					apr_table_set(r->headers_in, "OIC_ACCESS_TOKEN", access_token_str);
					apr_table_set(r->err_headers_out, "OIC_ACCESS_TOKEN", access_token_str);
					free(access_token_str);
				}

				// SCOPE
				char *scope_str = Get_Ox_Storage(session_value.c_str(), "scope");
				if (scope_str)
				{
					apr_table_set(r->subprocess_env, "OIC_SCOPE", scope_str);
					apr_table_set(r->headers_in, "OIC_SCOPE", scope_str);
					apr_table_set(r->err_headers_out, "OIC_SCOPE", scope_str);
					free(scope_str);
				}

				// STATE
				char *state_str = Get_Ox_Storage(session_value.c_str(), "state");
				char state[128];
				if (state_str)
				{
					strcpy(state, state_str);
					apr_table_set(r->subprocess_env, "OIC_STATE", state_str);
					apr_table_set(r->headers_in, "OIC_STATE", state_str);
					apr_table_set(r->err_headers_out, "OIC_STATE", state_str);
					free(state_str);
				}

				return 1;
			} 
			else 
			{
				APDEBUG(r, "session found for different path or hostname (cookie was for %s)", session.hostname.c_str());
			}
		}

		if (session_str) free(session_str);
	}

EXIT_has_connect_session:
	if(params.has_param("id_token") && params.has_param("access_token")) 
	{
		// user has been redirected, authenticate that and set cookie
		return 0;
	}
	else if(params.has_param("code") && params.has_param("state")) 
	{
		// user has been redirected, authenticate that and set cookie
		return -2;
	}


	return -1;
};

/*
* check the validation of session
*/
int validate_connect_session(request_rec *r, mod_ox_config *s_cfg, opkele::params_t& params) 
{
	std::string session_id, session_tmp;
	int token_timeout;

	// Get session id from params
	if (params.has_param("session_id"))
		session_tmp = params.get_param("session_id");
	else
		modox::make_rstring(32, session_tmp);

	// Get id token from params
	std::string id_token;
	if (params.has_param("id_token"))
		id_token = params.get_param("id_token");
	else
		return show_error(r, s_cfg, "unauthorized");

	// Get access token from params
	std::string access_token;
	if (params.has_param("access_token"))
		access_token = params.get_param("access_token");
	else
		return show_error(r, s_cfg, "unauthorized");

	// Get scope from params
	std::string scope;
	if (params.has_param("scope"))
		scope = params.get_param("scope");
	else
		return show_error(r, s_cfg, "unauthorized");

	// Get state from params
	std::string state;
	if (params.has_param("state"))
		state = params.get_param("state");
	else
		return show_error(r, s_cfg, "unauthorized");

	// Get expires_in from params
	std::string expires_in;
	if (params.has_param("expires_in"))
		expires_in = params.get_param("expires_in");
	else
		return show_error(r, s_cfg, "unauthorized");

	// session_id = session_id+"."+state
	session_id = session_tmp+"."+state;

	// Check status of id token
	token_timeout = oic_check_session(s_cfg, id_token.c_str(), session_id.c_str());
	if (token_timeout <= 0)
		return show_error(r, s_cfg, "Oxd failed to check session");

	// Save paraams into memcached
	int time_out = (int)atoi(expires_in.c_str());
	Set_Ox_Storage(session_id.c_str(), "session_id", session_tmp.c_str(), time_out);
	apr_table_set(r->headers_out, "OIC_SESSION_ID", session_tmp.c_str());

	Set_Ox_Storage(session_id.c_str(), "id_token", id_token.c_str(), time_out);
	apr_table_set(r->headers_out, "OIC_ID_TOKEN", id_token.c_str());

	Set_Ox_Storage(session_id.c_str(), "access_token", access_token.c_str(), time_out);
	apr_table_set(r->headers_out, "OIC_ACCESS_TOKEN", access_token.c_str());

	Set_Ox_Storage(session_id.c_str(), "scope", scope.c_str(), time_out);
	apr_table_set(r->headers_out, "OIC_SCOPE", scope.c_str());

	Set_Ox_Storage(session_id.c_str(), "state", state.c_str(), time_out);
	apr_table_set(r->headers_out, "OIC_STATE", state.c_str());

	return set_connect_cookie(r, s_cfg, params, session_id, token_timeout);
};