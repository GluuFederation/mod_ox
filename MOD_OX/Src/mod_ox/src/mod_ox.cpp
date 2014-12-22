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
#include "proc_connect.h"
#include "proc_uma.h"
#include "proc_saml.h"
#include "http_log.h"

#ifdef AP_DECLARE_MODULE
AP_DECLARE_MODULE(ox_module);
#endif

extern "C" module AP_MODULE_DECLARE_DATA ox_module;

#define APDEBUG(r, msg, ...) //ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, msg, __VA_ARGS__);
#define APWARN(r, msg, ...) //ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r, msg, __VA_ARGS__);
#define APERR(r, msg, ...) //ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, msg, __VA_ARGS__);

typedef const char *(*CMD_HAND_TYPE) ();

static void *create_mod_ox_config(apr_pool_t *p, char *s) {
	mod_ox_config *newcfg;
	newcfg = (mod_ox_config *) apr_pcalloc(p, sizeof(mod_ox_config));

	// General
	newcfg->auth_ntype = NULL;
	newcfg->auth_ztype = "TRUSTED_RP";
	newcfg->oxd_hostaddr = "localhost";
	newcfg->oxd_portnum = 8099;
	newcfg->memcached_hostaddr = "localhost";
	newcfg->memcached_portnum = 11211;
	newcfg->credit_path = NULL;
	newcfg->destination_url = NULL;
	newcfg->login_url = NULL;
	newcfg->logout_url = NULL;
	newcfg->postlogout_url = NULL;
	newcfg->logoutredirect_url = NULL;
	newcfg->admin_url = NULL;
	newcfg->discovery_url = NULL; 
	newcfg->client_name = NULL;

	// CONNECT
	newcfg->requested_acr = NULL;
	newcfg->response_type = NULL;

	// TRUSTED_RP_UMA
	newcfg->uma_discovery_url = NULL;
	newcfg->uma_resource_name = NULL;
	newcfg->uma_rs_host = NULL;
	memset((void *)&(newcfg->uma_am_host[0]), 0, sizeof(uma_am_host_config));
	memset((void *)&(newcfg->uma_am_host[1]), 0, sizeof(uma_am_host_config));
	memset((void *)&(newcfg->uma_am_host[2]), 0, sizeof(uma_am_host_config));
	newcfg->uma_sent_user_claims = "givenName+issuingIDP+mail+uid";
	
	// TRUSTED_RP_SAML
	newcfg->saml_redirect_url = NULL;

	// Etc
	newcfg->cookie_name = "ox_session_id";
	newcfg->cookie_path = NULL; 
	newcfg->cookie_lifespan = 0;
	newcfg->oic_redirect_url = NULL;
	newcfg->send_headers = FALSE;
	
	return (void *) newcfg;
}

static const char *set_mod_ox_auth_ntype(cmd_parms *parms, void *mconfig, const char *arg) { 
	mod_ox_config *s_cfg = (mod_ox_config *) mconfig;
	s_cfg->auth_ntype = (char *) arg; 
	return NULL; 
}

static const char *set_mod_ox_auth_ztype(cmd_parms *parms, void *mconfig, const char *arg) { 
	mod_ox_config *s_cfg = (mod_ox_config *) mconfig;
	s_cfg->auth_ztype = (char *) arg; 
	return NULL; 
}

// General Settings
static const char *set_mod_ox_oxd_hostaddr(cmd_parms *parms, void *mconfig, const char *arg) { 
	mod_ox_config *s_cfg = (mod_ox_config *) mconfig;
	s_cfg->oxd_hostaddr = (char *) arg; 
	return NULL; 
}
static const char *set_mod_ox_oxd_portnum(cmd_parms *parms, void *mconfig, const char *arg) {
	mod_ox_config *s_cfg = (mod_ox_config *) mconfig;
	s_cfg->oxd_portnum = atoi(arg);
	return NULL;
}
static const char *set_mod_ox_memcached_hostaddr(cmd_parms *parms, void *mconfig, const char *arg) { 
	mod_ox_config *s_cfg = (mod_ox_config *) mconfig;
	s_cfg->memcached_hostaddr = (char *) arg; 
	return NULL; 
} 
static const char *set_mod_ox_memcached_portnum(cmd_parms *parms, void *mconfig, const char *arg) {
	mod_ox_config *s_cfg = (mod_ox_config *) mconfig;
	s_cfg->memcached_portnum = atoi(arg);
	return NULL;
}
static const char *set_mod_ox_credit_path(cmd_parms *parms, void *mconfig, const char *arg) { 
	mod_ox_config *s_cfg = (mod_ox_config *) mconfig; 
	s_cfg->credit_path = (char *) arg; 
	return NULL; 
}
static const char *set_mod_ox_admin_url(cmd_parms *parms, void *mconfig, const char *arg) { 
	mod_ox_config *s_cfg = (mod_ox_config *) mconfig; 
	s_cfg->admin_url = (char *) arg; 
	return NULL; 
}
static const char *set_mod_ox_destination_url(cmd_parms *parms, void *mconfig, const char *arg) { 
	mod_ox_config *s_cfg = (mod_ox_config *) mconfig; 
	s_cfg->destination_url = (char *) arg; 
	return NULL; 
}
static const char *set_mod_ox_login_url(cmd_parms *parms, void *mconfig, const char *arg) { 
	mod_ox_config *s_cfg = (mod_ox_config *) mconfig; 
	s_cfg->login_url = (char *) arg; 
	return NULL; 
}
static const char *set_mod_ox_logout_url(cmd_parms *parms, void *mconfig, const char *arg) { 
	mod_ox_config *s_cfg = (mod_ox_config *) mconfig; 
	s_cfg->logout_url = (char *) arg; 
	return NULL; 
}
static const char *set_mod_ox_postlogout_url(cmd_parms *parms, void *mconfig, const char *arg) { 
	mod_ox_config *s_cfg = (mod_ox_config *) mconfig; 
	s_cfg->postlogout_url = (char *) arg; 
	return NULL; 
}
static const char *set_mod_ox_logoutredirect_url(cmd_parms *parms, void *mconfig, const char *arg) { 
	mod_ox_config *s_cfg = (mod_ox_config *) mconfig; 
	s_cfg->logoutredirect_url = (char *) arg; 
	return NULL; 
}
static const char *set_mod_ox_discovery_url(cmd_parms *parms, void *mconfig, const char *arg) { 
	mod_ox_config *s_cfg = (mod_ox_config *) mconfig; 
	s_cfg->discovery_url = (char *) arg; 
	return NULL; 
}
static const char *set_mod_ox_client_name(cmd_parms *parms, void *mconfig, const char *arg) { 
	mod_ox_config *s_cfg = (mod_ox_config *) mconfig; 
	s_cfg->client_name = (char *) arg; 
	return NULL; 
}

// TRUSTED_RP_CONNECT
static const char *set_mod_ox_requested_acr(cmd_parms *parms, void *mconfig, const char *arg) { 
	mod_ox_config *s_cfg = (mod_ox_config *) mconfig;
	s_cfg->requested_acr = (char *) arg; 
	return NULL; 
}

static const char *set_mod_ox_response_type(cmd_parms *parms, void *mconfig, const char *arg) { 
	mod_ox_config *s_cfg = (mod_ox_config *) mconfig;
	s_cfg->response_type = (char *) arg; 
	return NULL; 
}

// TRUSTED_RP_UMA
static const char *set_mod_ox_uma_discovery_url(cmd_parms *parms, void *mconfig, const char *arg) { 
	mod_ox_config *s_cfg = (mod_ox_config *) mconfig; 
	s_cfg->uma_discovery_url = (char *) arg; 
	return NULL; 
}
static const char *set_mod_ox_uma_resource_name(cmd_parms *parms, void *mconfig, const char *arg) { 
	mod_ox_config *s_cfg = (mod_ox_config *) mconfig; 
	s_cfg->uma_resource_name = (char *) arg; 
	return NULL; 
}
static const char *set_mod_ox_uma_rs_host(cmd_parms *parms, void *mconfig, const char *arg) { 
	mod_ox_config *s_cfg = (mod_ox_config *) mconfig; 
	s_cfg->uma_rs_host = (char *) arg; 
	return NULL; 
}
static const char *set_mod_ox_uma_am_host(cmd_parms *parms, void *mconfig, const char *arg, const char *exp) { 
	char *token[5];
	int i=0, j=0;
	mod_ox_config *s_cfg = (mod_ox_config *) mconfig; 
	if (s_cfg->uma_am_host[0].host == NULL)
		i = 0;
	else if (s_cfg->uma_am_host[1].host == NULL)
		i = 1;
	else if (s_cfg->uma_am_host[2].host == NULL)
		i = 2;
	else
		return NULL;

	s_cfg->uma_am_host[i].host = (char *) arg;
	token[j] = strtok((char *)exp, ";");
	while(token[j]!= NULL) {   
		s_cfg->uma_am_host[i].scope[j] = token[j];
		j++; if (j >= 5) break;		
		token[j] = strtok(NULL, ";");
	}

	return NULL; 
}

static const char *set_mod_ox_uma_attr_name(cmd_parms *parms, void *mconfig, const char *arg) { 
	mod_ox_config *s_cfg = (mod_ox_config *) mconfig; 
	s_cfg->uma_sent_user_claims = (char *) arg; 
	return NULL; 
}
/*
static const char *set_mod_ox_uma_attr_name(cmd_parms *parms, void *mconfig, const char *arg) { 
	mod_ox_config *s_cfg = (mod_ox_config *) mconfig;
	char *token[MAX_ATTR_NUM];
	int i;
	
	i = 0;
	token[i] = strtok((char *)arg, ";");
	while(token[i]!= NULL) {   
		s_cfg->uma_attr_name[i] = token[i];
		i++; if (i >= MAX_ATTR_NUM) break;		
		token[i] = strtok(NULL, ";");
	}
	return NULL; 
}
*/

// TRUSTED_RP_SAML
static const char *set_mod_ox_saml_redirect_url(cmd_parms *parms, void *mconfig, const char *arg) {
	mod_ox_config *s_cfg = (mod_ox_config *) mconfig;
	s_cfg->saml_redirect_url = (char *) arg;
	return NULL;
}

// Etc
static const char *set_mod_ox_cookie_path(cmd_parms *parms, void *mconfig, const char *arg) { 
	mod_ox_config *s_cfg = (mod_ox_config *) mconfig; 
	s_cfg->cookie_path = (char *) arg; 
	return NULL; 
}
static const char *set_mod_ox_connect_redirect_url(cmd_parms *parms, void *mconfig, const char *arg) {
	mod_ox_config *s_cfg = (mod_ox_config *) mconfig;
	s_cfg->oic_redirect_url = (char *) arg;
	return NULL;
}
static const char *set_mod_ox_send_headers(cmd_parms *parms, void *mconfig, const char *arg) {
	mod_ox_config *s_cfg = (mod_ox_config *) mconfig;
	if (!strcasecmp(arg, "on")) {
		s_cfg->send_headers = TRUE;
	}
	return NULL;
}

static const command_rec mod_ox_cmds[] = {
	AP_INIT_TAKE1("AuthnType", (CMD_HAND_TYPE) set_mod_ox_auth_ntype, NULL, OR_AUTHCFG,
	"AuthnType <string>"),
	AP_INIT_TAKE1("AuthzType", (CMD_HAND_TYPE) set_mod_ox_auth_ztype, NULL, OR_AUTHCFG,
	"AuthzType <string>"),
	AP_INIT_TAKE1("CookiePath", (CMD_HAND_TYPE) set_mod_ox_cookie_path, NULL, OR_AUTHCFG, 
	"CookiePath <path of cookie to use>"), 
	// General
	AP_INIT_TAKE1("OxdHostAddr", (CMD_HAND_TYPE) set_mod_ox_oxd_hostaddr, NULL, OR_AUTHCFG,
	"OxdHostAddr <string>"),
	AP_INIT_TAKE1("OxdPortNum", (CMD_HAND_TYPE) set_mod_ox_oxd_portnum, NULL, OR_AUTHCFG,
	"OxdPortNum <number>"),
	AP_INIT_TAKE1("MemcachedHostAddr", (CMD_HAND_TYPE) set_mod_ox_memcached_hostaddr, NULL, OR_AUTHCFG,
	"MemcachedHostAddr <string>"),
	AP_INIT_TAKE1("MemcachedPortNum", (CMD_HAND_TYPE) set_mod_ox_memcached_portnum, NULL, OR_AUTHCFG,
	"MemcachedPortNum <number>"),
	AP_INIT_TAKE1("AdminUrl", (CMD_HAND_TYPE) set_mod_ox_admin_url, NULL, OR_AUTHCFG,
	"AdminUrl <url string>"),
	AP_INIT_TAKE1("ApplicationDestinationUrl", (CMD_HAND_TYPE) set_mod_ox_destination_url, NULL, OR_AUTHCFG,
	"ApplicationDestinationUrl <url string>"),
	AP_INIT_TAKE1("ApplicationLoginUrl", (CMD_HAND_TYPE) set_mod_ox_login_url, NULL, OR_AUTHCFG,
	"ApplicationLoginUrl <url string>"),
	AP_INIT_TAKE1("ApplicationLogoutUrl", (CMD_HAND_TYPE) set_mod_ox_logout_url, NULL, OR_AUTHCFG,
	"ApplicationLogoutUrl <url string>"),
	AP_INIT_TAKE1("ApplicationPostLogoutUrl", (CMD_HAND_TYPE) set_mod_ox_postlogout_url, NULL, OR_AUTHCFG,
	"ApplicationPostLogoutUrl <url string>"),
	AP_INIT_TAKE1("ApplicationLogoutRedirectUrl", (CMD_HAND_TYPE) set_mod_ox_logoutredirect_url, NULL, OR_AUTHCFG,
	"ApplicationLogoutRedirectUrl <url string>"),
	AP_INIT_TAKE1("ClientCredsPath", (CMD_HAND_TYPE) set_mod_ox_credit_path, NULL, OR_AUTHCFG,
	"ClientCredsPath <string>"),
	AP_INIT_TAKE1("ConnectDiscoveryUrl", (CMD_HAND_TYPE) set_mod_ox_discovery_url, NULL, OR_AUTHCFG,
	"ConnectDiscoveryUrl <url string>"),
	AP_INIT_TAKE1("ClientName", (CMD_HAND_TYPE) set_mod_ox_client_name, NULL, OR_AUTHCFG,
	"ClientName <string>"),

	// TRUSTED_RP_CONNECT
	AP_INIT_TAKE1("RequestedACR", (CMD_HAND_TYPE) set_mod_ox_requested_acr, NULL, OR_AUTHCFG,
	"RequestedACR <string>"),
	AP_INIT_TAKE1("ResponseType", (CMD_HAND_TYPE) set_mod_ox_response_type, NULL, OR_AUTHCFG,
	"ResponseType <string>"),

	// TRUSTED_RP_UMA
	AP_INIT_TAKE1("UmaDiscoveryUrl", (CMD_HAND_TYPE) set_mod_ox_uma_discovery_url, NULL, OR_AUTHCFG,
	"UmaDiscoveryUrl <url string>"),
	AP_INIT_TAKE1("UmaResourceName", (CMD_HAND_TYPE) set_mod_ox_uma_resource_name, NULL, OR_AUTHCFG,
	"UmaResourceName <string>"),
	AP_INIT_TAKE1("UmaRsHost", (CMD_HAND_TYPE) set_mod_ox_uma_rs_host, NULL, OR_AUTHCFG,
	"UmaRsHost <string>"),
	AP_INIT_TAKE2("UmaAmHost", (CMD_HAND_TYPE) set_mod_ox_uma_am_host, NULL, OR_AUTHCFG,
	"UmaAmHost <string>"),
	AP_INIT_TAKE1("UmaSentUserClaims", (CMD_HAND_TYPE) set_mod_ox_uma_attr_name, NULL, OR_AUTHCFG,
	"UmaSentUserClaims <string>"),

	// TRUSTED_RP_SAML
	AP_INIT_TAKE1("SAMLRedirectUrl", (CMD_HAND_TYPE) set_mod_ox_saml_redirect_url, NULL, OR_AUTHCFG,
	"SAMLRedirectUrl <url string>"),

	// Etc
	AP_INIT_TAKE1("OicRedirectUrl", (CMD_HAND_TYPE) set_mod_ox_connect_redirect_url, NULL, OR_AUTHCFG,
	"OicRedirectUrl <url string>"),
	AP_INIT_TAKE1("SendHeaders", (CMD_HAND_TYPE) set_mod_ox_send_headers, NULL, OR_AUTHCFG, 
	"SendHeaders <on off>"), 
	
	{NULL}
};

//////////////////////////////////////////////////////////////////////////
///  Group of functions for log, check and alert
void mod_ox_log(const char *func_name, const char *log_msg)
{
	char logmsg[8192];
	sprintf(logmsg, "\n>>>>>>>> %s - %s <<<<<<<<\r\n", func_name, log_msg);
	fputs(logmsg, stderr);
	fflush(stderr);
}

void mod_ox_log(const char *func_name, const unsigned int log_int)
{
	char logmsg[8192];
	sprintf(logmsg, "\n>>>>>>>> %s - %d <<<<<<<<\r\n", func_name, log_int);
	fputs(logmsg, stderr);
	fflush(stderr);
}
/*
 * check auth type defined in apache .conf file
 * <ex> AuthType TRUSTED_RP_CONNECT
*/
static int mod_ox_check_auth_type(mod_ox_config *s_cfg)
{
	if (!s_cfg->auth_ntype || !s_cfg->auth_ztype)
		return -1;

	if (!strcasecmp(s_cfg->auth_ntype, "Connect") && !strcasecmp(s_cfg->auth_ztype, "Trusted_RP"))
		return TRUSTED_RP_CONNECT;
	else if (!strcasecmp(s_cfg->auth_ntype, "Connect") && !strcasecmp(s_cfg->auth_ztype, "RS_ONLY"))
		return TRUSTED_RP_CONNECT;
	else if (!strcasecmp(s_cfg->auth_ntype, "SAML") && !strcasecmp(s_cfg->auth_ztype, "Trusted_RP"))
		return TRUSTED_RP_SAML;
	else if (!strcasecmp(s_cfg->auth_ntype, "SAML") && !strcasecmp(s_cfg->auth_ztype, "RS_ONLY"))
		return TRUSTED_RP_SAML;
	else
		return -1;
}

/*
* check if uri is predefined uri defined in Apache .conf file
* <ex> ConnectRedirectUrl
*/
static int mod_ox_check_predefined_url(request_rec *r, mod_ox_config *s_cfg)
{
	apr_uri_t apuri;
	
	if (s_cfg->admin_url)
	{
		apr_uri_parse(r->pool, s_cfg->admin_url, &apuri);
		if (apuri.path != NULL)
		{
			if (!strcmp(r->uri, apuri.path))
				return ADMIN_PREDEFINED;
		}
	}

	if (s_cfg->login_url)
	{
		apr_uri_parse(r->pool, s_cfg->login_url, &apuri);
		if (apuri.path != NULL)
		{
			std::string redirect_uri;
			redirect_uri = apuri.path;
			redirect_uri += "redirect";
			if (!strcmp(r->uri, redirect_uri.c_str()))
				return LOGIN_PREDEFINED;
		}
	}

	if (s_cfg->logout_url)
	{
		apr_uri_parse(r->pool, s_cfg->logout_url, &apuri);
		if (apuri.path != NULL)
		{
			if (!strcmp(r->uri, apuri.path))
				return LOGOUT_PREDEFINED;
		}
	}
	
	return NONE_PREDEFINED;
};

/*
* check config infos defined in Apache .conf file
*/
static int mod_ox_check_configs(mod_ox_config *s_cfg, const int auth_type)
{
	// Check general configs
	if (!s_cfg->oxd_hostaddr || (s_cfg->oxd_portnum<0) || !s_cfg->memcached_hostaddr || (s_cfg->memcached_portnum<0) || \
		!s_cfg->discovery_url || !s_cfg->login_url || !s_cfg->client_name)
		return -1;

	// Check configs for each mode
	switch (auth_type)
	{
	case TRUSTED_RP_CONNECT:
		if (!s_cfg->response_type)
			return -1;		
		return 0;
	case TRUSTED_RP_UMA:
		if (!s_cfg->uma_discovery_url || !s_cfg->uma_resource_name || !s_cfg->uma_rs_host || \
			!s_cfg->uma_am_host[0].host || !s_cfg->uma_am_host[0].scope[0])
			return -1;
		return 0;
	case TRUSTED_RP_SAML:
		if (!s_cfg->saml_redirect_url)
			return -1;
		return 0;
	}

	return -1;
};

/*
* if error, return error message.
*/
int show_error(request_rec *r, mod_ox_config *s_cfg, char *e_message) {
	std::string uri_location;
	r->args = NULL;

	std::string name;
	r->uri ? name=r->uri: name=" ";
	std::string msg = e_message;
	return modox::show_html_error_message(r, name, msg);
};

/*
* if admin require to show client infos, return info message.
*/
int show_admin_page(request_rec *r, mod_ox_config *s_cfg) {
	std::string uri_location;
	char *issuer = Get_Ox_Storage(s_cfg->client_name, "oxd.issuer");
	char *authorization_endpoint = Get_Ox_Storage(s_cfg->client_name, "oxd.authorization_endpoint");
	char *client_id = Get_Ox_Storage(s_cfg->client_name, "oxd.client_id");
	char *client_secret = Get_Ox_Storage(s_cfg->client_name, "oxd.client_secret");

	std::string info_issuer = issuer?issuer:"";
	std::string info_authend = authorization_endpoint?authorization_endpoint:"";
	std::string info_clientid = client_id?client_id:"";
	std::string info_clientsecret = client_secret?client_secret:"";

	std::string result = 
		"<!DOCTYPE html PUBLIC \"-//W3C//DTD XHTML 1.0 Transitional//EN\" \"DTD/xhtml1-transitional.dtd\">"
		"<html><head>"
		"<style type=\"text/css\">"
		"body {background-color: #ffffff; color: #000000;}"
		"body, td, th, h1, h2 {font-family: sans-serif;}"
		"pre {margin: 0px; font-family: monospace;}"
		"a:link {color: #000099; text-decoration: none; background-color: #ffffff;}"
		"a:hover {text-decoration: underline;}"
		"table {border-collapse: collapse;}"
		".center {text-align: center;}"
		".center table { margin-left: auto; margin-right: auto; text-align: left;}"
		".center th { text-align: center !important; }"
		"td, th { border: 1px solid #000000; font-size: 75%; vertical-align: baseline;}"
		"h1 {font-size: 150%;}"
		"h2 {font-size: 125%;}"
		".p {text-align: left;}"
		".e {background-color: #cccccc; font-weight: bold; color: #000000;}"
		".h {background-color: #eeeeff; font-weight: bold; color: #000000;}"
		".v {background-color: #dddddd; color: #000000;}"
		".vr {background-color: #cccccc; text-align: right; color: #000000;}"
		"img {float: right; border: 0px;}"
		"hr {width: 600px; background-color: #cccccc; border: 0px; height: 1px; color: #000000;}"
		"</style>"
		"<title>Admin Page on OX</title></head>"
		"<body><div class=\"center\">"
		"<table border=\"0\" cellpadding=\"3\" width=\"600\">"
		"<tr class=\"h\"><td>"
		"<a href=\"http://www.gluu.org/\"><img border=\"0\" src=\"http://www.gluu.org/wp-content/uploads/2013/08/logo.png\" alt=\"Gluu Logo\" /></a><h1 class=\"p\">Mod OX Admin Page</h1>"
		"</td></tr>"
		"</table><br />"
		"<h2><a name=\"module_apache2handler\">Client Info</a></h2>"
		"<table border=\"0\" cellpadding=\"3\" width=\"600\">"
		"<tr><td class=\"e\">issuer </td><td class=\"v\">" + (info_issuer.empty()?"":info_issuer) + "</td></tr>"
		"<tr><td class=\"e\">authorization_endpoint </td><td class=\"v\">" + (info_authend.empty()?"":info_authend) + "</td></tr>"
		"<tr><td class=\"e\">client_id </td><td class=\"v\">" + (info_clientid.empty()?"":info_clientid) + "</td></tr>"
		"<tr><td class=\"e\">client_secret </td><td class=\"v\">" + (info_clientsecret.empty()?"":info_clientsecret) + "</td></tr>"
		"</table><br />"
		"</div></body></html>";

	if (issuer) free(issuer);
	if (authorization_endpoint) free(authorization_endpoint);
	if (client_id) free(client_id);
	if (client_secret) free(client_secret);

	r->args = NULL;
	// return HTTP_UNAUTHORIZED so that no further modules can produce output
	return modox::http_sendstring(r, result, HTTP_UNAUTHORIZED);
};

//////////////////////////////////////////////////////////////////////////
///  Group of functions for start authentication
static int start_authentication_session(request_rec *r, mod_ox_config *s_cfg, opkele::params_t& params, const int auth_type) 
{
	switch (auth_type)
	{
	case TRUSTED_RP_CONNECT:
		return start_connect_session(r, s_cfg, params);
	case TRUSTED_RP_UMA:
		return start_uma_session(r, s_cfg, params);
	case TRUSTED_RP_SAML:
		return start_saml_session(r, s_cfg, params);
	}

	return DECLINED;
}

static int has_valid_session(request_rec *r, mod_ox_config *s_cfg, opkele::params_t& params, const int logout, const int auth_type) 
{
	switch (auth_type)
	{
	case TRUSTED_RP_CONNECT:
		return has_connect_session(r, s_cfg, params, logout);
	case TRUSTED_RP_UMA:
		return has_uma_session(r, s_cfg, params);
	case TRUSTED_RP_SAML:
		return has_saml_session(r, s_cfg, params);
	}

	return -1;
};

static int validate_authentication_session(request_rec *r, mod_ox_config *s_cfg, opkele::params_t& params, const int auth_type) 
{
	switch (auth_type)
	{
	case TRUSTED_RP_CONNECT:
		return validate_connect_session(r, s_cfg, params);
	case TRUSTED_RP_UMA:
		return validate_uma_session(r, s_cfg, params);
	case TRUSTED_RP_SAML:
		return validate_saml_session(r, s_cfg, params);
	}

	return -1;
};

static int mod_ox_method_handler(request_rec *r) {
	mod_ox_config *s_cfg;
	int ret;
	int login = 0, logout = 0;

	// 1. get module config info
	s_cfg = (mod_ox_config *) ap_get_module_config(r->per_dir_config, &ox_module);

	// 2. if we're not enabled for this location/dir, decline doing anything
	const char *auth_string = ap_auth_type(r);
	if ((auth_string == NULL) || (strcasecmp(auth_string, "Gluu_ox")))
		return DECLINED;
	int auth_type = mod_ox_check_auth_type(s_cfg);
	if (auth_type < 0)
		return show_error(r, s_cfg, "Invalid OX parameters, Please check AuthnType and AuthzType in Apache");

	// 3. check config infos in Apache conf file
	if (mod_ox_check_configs(s_cfg, auth_type) != 0)
		return show_error(r, s_cfg, "Invalid OX parameters, Please check ox.conf in Apache");

	// 4. init memcached storage
	if (Init_Ox_Storage(s_cfg->memcached_hostaddr, s_cfg->memcached_portnum) != 0)
		return show_error(r, s_cfg, "Failed to connecting Memcached Server");

	// 5. if access redirect, ok
	ret = mod_ox_check_predefined_url(r, s_cfg);
	switch (ret)
	{
	case NONE_PREDEFINED:
		break;
	case LOGIN_PREDEFINED:
		login = 1;
		break;
	case LOGOUT_PREDEFINED:
		logout = 1;
		break;
	}

	// 6. make a record of our being called
	APDEBUG(r, "*** %s module has been called ***", PACKAGE_STRING);

	// 7. parse the get/post params
	opkele::params_t params;
	modox::get_request_params(r, params);

	// 8. check session info
	ret = has_valid_session(r, s_cfg, params, logout, auth_type);
	if (ret == 1)			// if
	{ 
		// user has valid session
		r->user = apr_pstrdup(r->pool, "*");
		ret = OK;
	}
	else if (ret == 0)		// if
	{ 
		// user has been redirected, authenticate them and set cookie
		ret = validate_authentication_session(r, s_cfg, params, auth_type);
		if (ret == 0)
		{
			r->user = apr_pstrdup(r->pool, "*");
			ret = OK;
		}
	}
	else if (ret == -1)					// if no
	{
		if (login == 1)
			return modox::show_html_redirect_page(r, s_cfg->login_url);
		// user is posting id URL, or we're in single OP mode and already have one, so try to authenticate
		ret = start_authentication_session(r, s_cfg, params, auth_type);
	}
	else
		return ret;

	//Close_Ox_Storage();
	// 9. if access redirect, ok
	if (ret == OK)
	{
		ret = mod_ox_check_predefined_url(r, s_cfg);
		switch (ret)
		{
		case ADMIN_PREDEFINED:
			return show_admin_page(r, s_cfg);
		}

		return OK;
	}

	return ret;
}

#if AP_MODULE_MAGIC_AT_LEAST(20080403,1)
static authz_status user_check_authorization(request_rec *r, const char *require_args, const void *parsed_require_args)
{
	const char *t, *w;

	if (!r->user) {
		return AUTHZ_DENIED_NO_USER;
	}

	t = require_args;
	while ((w = ap_getword_conf(r->pool, &t)) && w[0]) {
		if (!strcmp(r->user, w)) {
			return AUTHZ_GRANTED;
		}
	}

	return AUTHZ_DENIED;
}

static authz_status validuser_check_authorization(request_rec *r, const char *require_line, const void *parsed_require_line)
{
	if (!r->user) {
		return AUTHZ_DENIED_NO_USER;
	}

	return AUTHZ_GRANTED;
}

static const authz_provider authz_user_provider =
{
	&user_check_authorization,
	NULL,
};

static const authz_provider authz_validuser_provider =
{
	&validuser_check_authorization,
	NULL,
};
#else
static int mod_ox_check_user_access(request_rec *r) {
	//mod_ox_config *s_cfg;
	//s_cfg = (mod_ox_config *) ap_get_module_config(r->per_dir_config, &uma_module);
	char *user = r->user;
	int m = r->method_number;
	int required_user = 0;
	register int x;
	const char *t, *w;
	const apr_array_header_t *reqs_arr = ap_requires(r);
	require_line *reqs;

	if (!reqs_arr) 
		return DECLINED;

	reqs = (require_line *)reqs_arr->elts;
	for (x = 0; x < reqs_arr->nelts; x++) {
		if (!(reqs[x].method_mask & (AP_METHOD_BIT << m))) 
			continue;

		t = reqs[x].requirement;
		w = ap_getword_white(r->pool, &t);
		if (!strcasecmp(w, "valid-user"))
			return OK;

		if (!strcasecmp(w, "user")) {
			required_user = 1;
			while (t[0]) {
				w = ap_getword_conf(r->pool, &t);
				if (!strcmp(user, w))
					return OK;
			}
		}
	}

	if (!required_user)
		return DECLINED;

	APERR(r, "Access to %s failed: user '%s' invalid", r->uri, user);
	ap_note_auth_failure(r);
	return HTTP_UNAUTHORIZED;
}
#endif

static void mod_ox_register_hooks (apr_pool_t *p) {
#if AP_MODULE_MAGIC_AT_LEAST(20080403,1)
	ap_hook_check_authn(mod_ox_method_handler,
		NULL,
		NULL,
		APR_HOOK_MIDDLE,
		AP_AUTH_INTERNAL_PER_CONF);
	ap_register_auth_provider(p,
		AUTHZ_PROVIDER_GROUP,
		"valid-user",
		AUTHZ_PROVIDER_VERSION,
		&authz_validuser_provider,
		AP_AUTH_INTERNAL_PER_CONF);
	ap_register_auth_provider(p,
		AUTHZ_PROVIDER_GROUP,
		"user",
		AUTHZ_PROVIDER_VERSION,
		&authz_user_provider,
		AP_AUTH_INTERNAL_PER_CONF);
#else
	ap_hook_check_user_id(mod_ox_method_handler, NULL, NULL, APR_HOOK_MIDDLE);
	ap_hook_auth_checker(mod_ox_check_user_access, NULL, NULL, APR_HOOK_MIDDLE);
#endif
}

//module 
module AP_MODULE_DECLARE_DATA ox_module = {
	STANDARD20_MODULE_STUFF,
	create_mod_ox_config,
	NULL, // config merge function - default is to override
	NULL,
	NULL,
	mod_ox_cmds,
	mod_ox_register_hooks,
};
 
