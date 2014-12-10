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

#ifndef __MOD_UMA_H_
#define __MOD_UMA_H_

#ifdef WIN32
#pragma comment(lib, "libhttpd.lib")
#pragma comment(lib, "libapr-1.lib")
#pragma comment(lib, "libaprutil-1.lib")
#pragma warning (disable: 4267)
#else
#pragma GCC diagnostic ignored "-Wwrite-strings"
#pragma GCC diagnostic ignored "-Wunused-but-set-variable"
#pragma GCC diagnostic ignored "-Wunused-variable"
#endif

#include <string>

#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_log.h"
#include "http_main.h"
#include "http_protocol.h"
#include "http_request.h"
#include "util_script.h"
#include "http_connection.h"
#include "mod_auth.h"

#include "apr_strings.h"

#include <stdio.h>

#include "opk_types.h"
#include "opk_exception.h"
#include "opk_util.h"
#include "json_main.h"
#include "apr_memcache.h"
#include "storage.h"
#include "oidc_types.h"
#include "oidc_utils.h"
#include "oidc_http.h"

/* Header enctype for POSTed form data */
#define DEFAULT_POST_ENCTYPE "application/x-www-form-urlencoded"

typedef struct {
	apr_ipsubnet_t *ipsubnet;
} bigip_trust_proxy_t;

typedef struct {
	apr_array_header_t *trust_proxies;  /* Array of bigip_trust_proxy_t */
} bigip_srv_config_t;

typedef struct {
	int ssl_required;
} bigip_dir_config_t;

#define BIGIP_SRV_CONFIG(r) (bigip_srv_config_t *)ap_get_module_config((r)->server->module_config, &bigip_module)
#define BIGIP_DIR_CONFIG(r) (bigip_dir_config_t *)ap_get_module_config((r)->per_dir_config, &bigip_module)

#define BIGIP_CLIENT_TRUSTED_NOTE       "bigip-is-client-trusted"
#define BIGIP_VIA_NOTE                  "bigip-header-via"
#define BIGIP_X_FORWARDED_FOR_NOTE      "bigip-header-x-forwarded-for"
#define BIGIP_X_FORWARDED_PROTO_NOTE    "bigip-header-x-forwarded-proto"
#define BIGIP_HTTPS_NOTE                "bigip-https"
#define BIGIP_HTTPS_ON                  "on"
#define BIGIP_HTTPS_OFF                 "off"

#define DEBUG 1

/* overwrite package vars set by apache */
#undef PACKAGE_BUGREPORT
#undef PACKAGE_NAME
#undef PACKAGE_STRING
#undef PACKAGE_TARNAME
#undef PACKAGE_VERSION
#undef PACKAGE_URL

/* Header enctype for POSTed form data */
#define DEFAULT_POST_ENCTYPE "application/x-www-form-urlencoded"

/* Attribute Exchange */
#define AX_NAMESPACE "http://openid.net/srv/ax/1.0"
#define DEFAULT_AX_NAMESPACE_ALIAS "ax"

/* Auth Mode */
#define TRUSTED_RP_NONE		0
#define TRUSTED_RP_CONNECT		1
#define TRUSTED_RP_UMA		2
#define TRUSTED_RP_SAML	3

/* Max Lengths */
#define MAX_ATTR_NUM		20

/* Reture values for predefined URL */
enum {
	NONE_PREDEFINED,
	ADMIN_PREDEFINED,
	LOGIN_PREDEFINED,
	LOGOUT_PREDEFINED
};

/* config variables */
typedef struct {
	char *host;
	char *scope[5];
} uma_am_host_config;

typedef struct {
	char *auth_ntype;
	char *auth_ztype;

	// General
	char *oxd_hostaddr;
	int oxd_portnum;
	char *memcached_hostaddr;
	int memcached_portnum;
	char *credit_path;
	char *admin_url;
	char *destination_url;
	char *login_url;
	char *logout_url;
	char *postlogout_url;
	char *logoutredirect_url;
	char *discovery_url;
	char *client_name;

	// TRUSTED_RP_CONNECT
	char *requested_acr;
	char *response_type;

	// TRUSTED_RP_UMA
	char *uma_discovery_url;
	char *uma_resource_name;
	char *uma_rs_host;
	uma_am_host_config uma_am_host[3];
	char *uma_sent_user_claims;

	// TRUSTED_RP_SAML
	char *saml_redirect_url;

	// Etc
	const char *cookie_name;
	int cookie_lifespan;
	char *cookie_path;
	char *oic_redirect_url;
	bool send_headers;
} mod_ox_config;

/* mod_auth_openid includes */
#include "config.h"

void mod_ox_log(const char *func_name, const char *log_msg);
int show_error(request_rec *r, mod_ox_config *s_cfg, char *e_message);

#define APDEBUG(r, msg, ...) //ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, msg, __VA_ARGS__);
#define APWARN(r, msg, ...) //ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r, msg, __VA_ARGS__);
#define APERR(r, msg, ...) //ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, msg, __VA_ARGS__);

#endif
