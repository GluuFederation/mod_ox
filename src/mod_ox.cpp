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

	newcfg->AuthnType = NULL;
	newcfg->CookiePath = NULL;
	newcfg->ApplicationDestinationUrl = NULL;
	newcfg->ClientCredsPath = NULL;
	newcfg->SendHeaders = SETNONE;

	// Valid only if AuthnType=SAML
	newcfg->SAMLRedirectUrl = NULL;

	// oxd configuration
	newcfg->OxdHostAddr = "127.0.0.1";
	newcfg->OxdPortNum = 8099;

	// memcached configuration
	newcfg->MemcachedHostAddr = "127.0.0.1";
	newcfg->MemcachedPortNum = 11211;
	
	// OpenID Connect
	newcfg->OpenIDProvider = NULL;
	newcfg->OpenIDClientRedirectURIs = NULL; 
	newcfg->OpenIDRequestedScopes = "openid";
	newcfg->OpenIDClientName = NULL;
	newcfg->OpenIDRequestedACR = NULL;
	newcfg->OpenIDResponseType = NULL;

	// UMA
	newcfg->UmaAuthorizationServer = NULL;
	newcfg->UmaResourceName = NULL;
	newcfg->UmaGetScope = NULL;
	newcfg->UmaPutScope = NULL;
	newcfg->UmaPostScope = NULL;
	newcfg->UmaDeleteScope = NULL;

	// Logout
	newcfg->ApplicationPostLogoutUrl = NULL;
	newcfg->ApplicationPostLogoutRedirectUrl = NULL;
	newcfg->oxLogoutUrl = NULL;

	// Etc
	newcfg->admin_url = NULL;
	newcfg->uma_rs_host = NULL;
	newcfg->uma_am_host = NULL;
	newcfg->uma_sent_user_claims = "givenName+issuingIDP+mail+uid";
	newcfg->cookie_name = "ox_session_id";
	newcfg->cookie_lifespan = 0;
	
	return (void *) newcfg;
}

static const char *set_mod_ox_auth_ntype(cmd_parms *parms, void *mconfig, const char *arg) { 
	mod_ox_config *s_cfg = (mod_ox_config *) mconfig;
	s_cfg->AuthnType = (char *) arg; 
	return NULL; 
}
static const char *set_mod_ox_cookie_path(cmd_parms *parms, void *mconfig, const char *arg) { 
	mod_ox_config *s_cfg = (mod_ox_config *) mconfig; 
	s_cfg->CookiePath = (char *) arg; 
	return NULL; 
}
static const char *set_mod_ox_destination_url(cmd_parms *parms, void *mconfig, const char *arg) { 
	mod_ox_config *s_cfg = (mod_ox_config *) mconfig; 
	s_cfg->ApplicationDestinationUrl = (char *) arg; 
	return NULL; 
}
static const char *set_mod_ox_credit_path(cmd_parms *parms, void *mconfig, const char *arg) { 
	mod_ox_config *s_cfg = (mod_ox_config *) mconfig; 
	s_cfg->ClientCredsPath = (char *) arg; 
	return NULL; 
}
static const char *set_mod_ox_send_headers(cmd_parms *parms, void *mconfig, const char *arg) {
	mod_ox_config *s_cfg = (mod_ox_config *) mconfig;
	if (!strcasecmp(arg, "on")) {
		s_cfg->SendHeaders = SETON;
	}
	if (!strcasecmp(arg, "off")) {
		s_cfg->SendHeaders = SETOFF;
	}
	return NULL;
}

// Valid only if AuthnType=SAML
static const char *set_mod_ox_saml_redirect_url(cmd_parms *parms, void *mconfig, const char *arg) {
	mod_ox_config *s_cfg = (mod_ox_config *) mconfig;
	s_cfg->SAMLRedirectUrl = (char *) arg;
	return NULL;
}

// oxd configuration
static const char *set_mod_ox_oxd_hostaddr(cmd_parms *parms, void *mconfig, const char *arg) { 
	mod_ox_config *s_cfg = (mod_ox_config *) mconfig;
	s_cfg->OxdHostAddr = (char *) arg; 
	return NULL; 
}
static const char *set_mod_ox_oxd_portnum(cmd_parms *parms, void *mconfig, const char *arg) {
	mod_ox_config *s_cfg = (mod_ox_config *) mconfig;
	s_cfg->OxdPortNum = atoi(arg);
	return NULL;
}

// memcached configuration
static const char *set_mod_ox_memcached_hostaddr(cmd_parms *parms, void *mconfig, const char *arg) { 
	mod_ox_config *s_cfg = (mod_ox_config *) mconfig;
	s_cfg->MemcachedHostAddr = (char *) arg; 
	return NULL; 
} 
static const char *set_mod_ox_memcached_portnum(cmd_parms *parms, void *mconfig, const char *arg) {
	mod_ox_config *s_cfg = (mod_ox_config *) mconfig;
	s_cfg->MemcachedPortNum = atoi(arg);
	return NULL;
}

// OpenID Connect
static const char *set_mod_ox_openid_provider(cmd_parms *parms, void *mconfig, const char *arg) { 
	mod_ox_config *s_cfg = (mod_ox_config *) mconfig; 
	s_cfg->OpenIDProvider = (char *) arg; 
	return NULL; 
}
static const char *set_mod_ox_openid_client_redirecturis(cmd_parms *parms, void *mconfig, const char *arg) { 
	mod_ox_config *s_cfg = (mod_ox_config *) mconfig; 
	s_cfg->OpenIDClientRedirectURIs = (char *) arg; 
	return NULL; 
}
static const char *set_mod_ox_openid_requested_scopes(cmd_parms *parms, void *mconfig, const char *arg) { 
	mod_ox_config *s_cfg = (mod_ox_config *) mconfig; 
	s_cfg->OpenIDRequestedScopes = (char *) arg; 
	return NULL; 
}
static const char *set_mod_ox_openid_client_name(cmd_parms *parms, void *mconfig, const char *arg) { 
	mod_ox_config *s_cfg = (mod_ox_config *) mconfig; 
	s_cfg->OpenIDClientName = (char *) arg; 
	return NULL; 
}
static const char *set_mod_ox_openid_requested_acr(cmd_parms *parms, void *mconfig, const char *arg) { 
	mod_ox_config *s_cfg = (mod_ox_config *) mconfig;
	s_cfg->OpenIDRequestedACR = (char *) arg; 
	return NULL; 
}

static const char *set_mod_ox_openid_response_type(cmd_parms *parms, void *mconfig, const char *arg) { 
	mod_ox_config *s_cfg = (mod_ox_config *) mconfig;
	s_cfg->OpenIDResponseType = (char *) arg; 
	return NULL; 
}

// UMA
static const char *set_mod_ox_uma_authorization_server(cmd_parms *parms, void *mconfig, const char *arg) { 
	mod_ox_config *s_cfg = (mod_ox_config *) mconfig; 
	s_cfg->UmaAuthorizationServer = (char *) arg; 
	return NULL; 
}
static const char *set_mod_ox_uma_resource_name(cmd_parms *parms, void *mconfig, const char *arg) { 
	mod_ox_config *s_cfg = (mod_ox_config *) mconfig; 
	s_cfg->UmaResourceName = (char *) arg; 
	return NULL; 
}
static const char *set_mod_ox_uma_get_scope(cmd_parms *parms, void *mconfig, const char *arg) { 
	mod_ox_config *s_cfg = (mod_ox_config *) mconfig; 
	s_cfg->UmaGetScope = (char *) arg; 
	return NULL; 
}
static const char *set_mod_ox_uma_put_scope(cmd_parms *parms, void *mconfig, const char *arg) { 
	mod_ox_config *s_cfg = (mod_ox_config *) mconfig; 
	s_cfg->UmaPutScope = (char *) arg; 
	return NULL; 
}
static const char *set_mod_ox_uma_post_scope(cmd_parms *parms, void *mconfig, const char *arg) { 
	mod_ox_config *s_cfg = (mod_ox_config *) mconfig; 
	s_cfg->UmaPostScope = (char *) arg; 
	return NULL; 
}
static const char *set_mod_ox_uma_delete_scope(cmd_parms *parms, void *mconfig, const char *arg) { 
	mod_ox_config *s_cfg = (mod_ox_config *) mconfig; 
	s_cfg->UmaDeleteScope = (char *) arg; 
	return NULL; 
}

// Logout
static const char *set_mod_ox_application_postlogout_url(cmd_parms *parms, void *mconfig, const char *arg) { 
	mod_ox_config *s_cfg = (mod_ox_config *) mconfig; 
	s_cfg->ApplicationPostLogoutUrl = (char *) arg; 
	return NULL; 
}
static const char *set_mod_ox_application_postlogoutredirect_url(cmd_parms *parms, void *mconfig, const char *arg) { 
	mod_ox_config *s_cfg = (mod_ox_config *) mconfig; 
	s_cfg->ApplicationPostLogoutRedirectUrl = (char *) arg; 
	return NULL; 
}
static const char *set_mod_ox_logout_url(cmd_parms *parms, void *mconfig, const char *arg) { 
	mod_ox_config *s_cfg = (mod_ox_config *) mconfig; 
	s_cfg->oxLogoutUrl = (char *) arg; 
	return NULL; 
}

// Etc
static const char *set_mod_ox_admin_url(cmd_parms *parms, void *mconfig, const char *arg) { 
	mod_ox_config *s_cfg = (mod_ox_config *) mconfig; 
	s_cfg->admin_url = (char *) arg; 
	return NULL; 
}
static const char *set_mod_ox_uma_rs_host(cmd_parms *parms, void *mconfig, const char *arg) { 
	mod_ox_config *s_cfg = (mod_ox_config *) mconfig; 
	s_cfg->uma_rs_host = (char *) arg; 
	return NULL; 
}
static const char *set_mod_ox_uma_am_host(cmd_parms *parms, void *mconfig, const char *arg, const char *exp) { 
	mod_ox_config *s_cfg = (mod_ox_config *) mconfig; 
	s_cfg->uma_am_host = (char *) arg; 
	return NULL; 
}
static const char *set_mod_ox_uma_attr_name(cmd_parms *parms, void *mconfig, const char *arg) { 
	mod_ox_config *s_cfg = (mod_ox_config *) mconfig; 
	s_cfg->uma_sent_user_claims = (char *) arg; 
	return NULL; 
}

static const command_rec mod_ox_cmds[] = {
	AP_INIT_TAKE1("AuthnType", (CMD_HAND_TYPE) set_mod_ox_auth_ntype, NULL, OR_AUTHCFG,
	"AuthnType <string>"),
	AP_INIT_TAKE1("CookiePath", (CMD_HAND_TYPE) set_mod_ox_cookie_path, NULL, OR_AUTHCFG, 
	"CookiePath <path of cookie to use>"), 
	AP_INIT_TAKE1("ApplicationDestinationUrl", (CMD_HAND_TYPE) set_mod_ox_destination_url, NULL, OR_AUTHCFG,
	"ApplicationDestinationUrl <url string>"),
	AP_INIT_TAKE1("ClientCredsPath", (CMD_HAND_TYPE) set_mod_ox_credit_path, NULL, OR_AUTHCFG,
	"ClientCredsPath <string>"),
	AP_INIT_TAKE1("SendHeaders", (CMD_HAND_TYPE) set_mod_ox_send_headers, NULL, OR_AUTHCFG, 
	"SendHeaders <on off>"),

	// Valid only if AuthnType=SAML
	AP_INIT_TAKE1("SAMLRedirectUrl", (CMD_HAND_TYPE) set_mod_ox_saml_redirect_url, NULL, OR_AUTHCFG,
	"SAMLRedirectUrl <url string>"),

	// oxd configuration
	AP_INIT_TAKE1("OxdHostAddr", (CMD_HAND_TYPE) set_mod_ox_oxd_hostaddr, NULL, OR_AUTHCFG,
	"OxdHostAddr <string>"),
	AP_INIT_TAKE1("OxdPortNum", (CMD_HAND_TYPE) set_mod_ox_oxd_portnum, NULL, OR_AUTHCFG,
	"OxdPortNum <number>"),

	// memcached configuration
	AP_INIT_TAKE1("MemcachedHostAddr", (CMD_HAND_TYPE) set_mod_ox_memcached_hostaddr, NULL, OR_AUTHCFG,
	"MemcachedHostAddr <string>"),
	AP_INIT_TAKE1("MemcachedPortNum", (CMD_HAND_TYPE) set_mod_ox_memcached_portnum, NULL, OR_AUTHCFG,
	"MemcachedPortNum <number>"),

	// OpenID Connect
	AP_INIT_TAKE1("OpenIDProvider", (CMD_HAND_TYPE) set_mod_ox_openid_provider, NULL, OR_AUTHCFG,
	"OpenIDProvider <url string>"),
	AP_INIT_TAKE1("OpenIDClientRedirectURIs", (CMD_HAND_TYPE) set_mod_ox_openid_client_redirecturis, NULL, OR_AUTHCFG,
	"OpenIDClientRedirectURIs <url string>"),
	AP_INIT_TAKE1("OpenIDRequestedScopes", (CMD_HAND_TYPE) set_mod_ox_openid_requested_scopes, NULL, OR_AUTHCFG,
	"OpenIDRequestedScopes <string>"),
	AP_INIT_TAKE1("OpenIDClientName", (CMD_HAND_TYPE) set_mod_ox_openid_client_name, NULL, OR_AUTHCFG,
	"OpenIDClientName <string>"),
	AP_INIT_TAKE1("OpenIDRequestedACR", (CMD_HAND_TYPE) set_mod_ox_openid_requested_acr, NULL, OR_AUTHCFG,
	"OpenIDRequestedACR <string>"),
	AP_INIT_TAKE1("OpenIDResponseType", (CMD_HAND_TYPE) set_mod_ox_openid_response_type, NULL, OR_AUTHCFG,
	"OpenIDResponseType <string>"),

	// UMA
	AP_INIT_TAKE1("UmaAuthorizationServer", (CMD_HAND_TYPE) set_mod_ox_uma_authorization_server, NULL, OR_AUTHCFG,
	"UmaAuthorizationServer <string>"),
	AP_INIT_TAKE1("UmaResourceName", (CMD_HAND_TYPE) set_mod_ox_uma_resource_name, NULL, OR_AUTHCFG,
	"UmaResourceName <string>"),
	AP_INIT_TAKE1("UmaGetScope", (CMD_HAND_TYPE) set_mod_ox_uma_get_scope, NULL, OR_AUTHCFG,
	"UmaGetScope <string>"),
	AP_INIT_TAKE1("UmaPutScope", (CMD_HAND_TYPE) set_mod_ox_uma_put_scope, NULL, OR_AUTHCFG,
	"UmaPutScope <url string>"),
	AP_INIT_TAKE1("UmaPostScope", (CMD_HAND_TYPE) set_mod_ox_uma_post_scope, NULL, OR_AUTHCFG,
	"UmaPostScope <url string>"),
	AP_INIT_TAKE1("UmaDeleteScope", (CMD_HAND_TYPE) set_mod_ox_uma_delete_scope, NULL, OR_AUTHCFG,
	"UmaDeleteScope <url string>"),

	// Logout
	AP_INIT_TAKE1("ApplicationPostLogoutUrl", (CMD_HAND_TYPE) set_mod_ox_application_postlogout_url, NULL, OR_AUTHCFG,
	"ApplicationPostLogoutUrl <url string>"),
	AP_INIT_TAKE1("ApplicationPostLogoutRedirectUrl", (CMD_HAND_TYPE) set_mod_ox_application_postlogoutredirect_url, NULL, OR_AUTHCFG,
	"ApplicationPostLogoutRedirectUrl <url string>"),
	AP_INIT_TAKE1("oxLogoutUrl", (CMD_HAND_TYPE) set_mod_ox_logout_url, NULL, OR_AUTHCFG,
	"oxLogoutUrl <url string>"),

	// Etc
	AP_INIT_TAKE1("AdminUrl", (CMD_HAND_TYPE) set_mod_ox_admin_url, NULL, OR_AUTHCFG,
	"AdminUrl <url string>"),
	AP_INIT_TAKE1("UmaRsHost", (CMD_HAND_TYPE) set_mod_ox_uma_rs_host, NULL, OR_AUTHCFG,
	"UmaRsHost <string>"),
	AP_INIT_TAKE2("UmaAmHost", (CMD_HAND_TYPE) set_mod_ox_uma_am_host, NULL, OR_AUTHCFG,
	"UmaAmHost <string>"),
	AP_INIT_TAKE1("UmaSentUserClaims", (CMD_HAND_TYPE) set_mod_ox_uma_attr_name, NULL, OR_AUTHCFG,
	"UmaSentUserClaims <string>"),

	
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
	if (!s_cfg->AuthnType)
		return -1;

	if (!strcasecmp(s_cfg->AuthnType, "Connect"))
		return TRUSTED_RP_CONNECT;
	if (!strcasecmp(s_cfg->AuthnType, "UMA"))
		return TRUSTED_RP_UMA;
	else if (!strcasecmp(s_cfg->AuthnType, "SAML"))
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

	// Checking Admin Page
	if (s_cfg->admin_url)
	{
		apr_uri_parse(r->pool, s_cfg->admin_url, &apuri);
		if (apuri.path != NULL)
		{
			if (!strcmp(r->uri, apuri.path))
				return ADMIN_PREDEFINED;
		}
	}

	// Checking Redirect page
	if (s_cfg->OpenIDClientRedirectURIs)
	{
		apr_uri_parse(r->pool, s_cfg->OpenIDClientRedirectURIs, &apuri);
		if (apuri.path != NULL)
		{
			if (!strcmp(r->uri, apuri.path))
				return LOGIN_PREDEFINED;
		}
	}

	// Checking Logout page
	if (s_cfg->oxLogoutUrl)
	{
		apr_uri_parse(r->pool, s_cfg->oxLogoutUrl, &apuri);
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
static int mod_ox_check_configs(request_rec *r, mod_ox_config *s_cfg, const int auth_type)
{
	// Check general configs
	if (!s_cfg->AuthnType || !s_cfg->CookiePath || (s_cfg->SendHeaders==SETNONE) || !s_cfg->OpenIDProvider || \
		!s_cfg->OpenIDClientRedirectURIs || !s_cfg->OpenIDResponseType)
		return -1;

	// Check configs for each mode
	switch (auth_type)
	{
	case TRUSTED_RP_CONNECT:
		if (!s_cfg->OpenIDResponseType)
			return -1;		
		return 0;
	case TRUSTED_RP_UMA:
		if (!s_cfg->UmaAuthorizationServer || !s_cfg->UmaResourceName)
		{
			return -1;
		}

		s_cfg->uma_rs_host = (char *)r->hostname;
		s_cfg->uma_am_host = s_cfg->UmaAuthorizationServer;
		return 0;
	case TRUSTED_RP_SAML:
		if (!s_cfg->SAMLRedirectUrl)
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
	char *issuer = Get_Ox_Storage(s_cfg->OpenIDClientName, "oxd.issuer");
	char *authorization_endpoint = Get_Ox_Storage(s_cfg->OpenIDClientName, "oxd.authorization_endpoint");
	char *client_id = Get_Ox_Storage(s_cfg->OpenIDClientName, "oxd.client_id");
	char *client_secret = Get_Ox_Storage(s_cfg->OpenIDClientName, "oxd.client_secret");

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
		return has_uma_session(r, s_cfg, params, logout);
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
	if (mod_ox_check_configs(r, s_cfg, auth_type) != 0)
		return show_error(r, s_cfg, "Invalid OX parameters, Please check ox.conf in Apache");

	// 4. init memcached storage
	if (Init_Ox_Storage(s_cfg->MemcachedHostAddr, s_cfg->MemcachedPortNum) != 0)
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
		{
			return modox::show_html_redirect_page(r, s_cfg->OpenIDClientRedirectURIs);
		}
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
 
