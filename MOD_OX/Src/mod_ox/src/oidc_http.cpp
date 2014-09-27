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

namespace modox {
	using namespace std;

	int http_sendstring(request_rec *r, string s, int success_rvalue) {
		// no idea why the following line only sometimes worked.....
		//apr_table_setn(r->headers_out, "Content-Type", "text/html");
		ap_set_content_type(r, "text/html");
		const char *c_s = s.c_str();
		conn_rec *c = r->connection;
		apr_bucket *b;
		apr_bucket_brigade *bb = apr_brigade_create(r->pool, c->bucket_alloc);
		b = apr_bucket_transient_create(c_s, strlen(c_s), c->bucket_alloc);
		APR_BRIGADE_INSERT_TAIL(bb, b);
		b = apr_bucket_eos_create(c->bucket_alloc);
		APR_BRIGADE_INSERT_TAIL(bb, b);

		if (ap_pass_brigade(r->output_filters, bb) != APR_SUCCESS)
			return HTTP_INTERNAL_SERVER_ERROR;
		return success_rvalue;
	};

	int send_form_post(request_rec *r, string location) {
		string::size_type last = location.find('?', 0);
		string url = (last != string::npos) ? location.substr(0, last) : location;

		params_t params;
		if(url.size() < location.size())
			params = parse_query_string(location.substr(url.size()+1));

		string inputs = "";
		map<string,string>::iterator iter;
		for(iter = params.begin(); iter != params.end(); iter++) {
			string key(iter->first);
			inputs += "<input type=\"hidden\" name=\"" + key + "\" value=\"" + params[key] + "\" />";
		}

		string result = 
			"<html><head><title>redirection</title></head><body onload=\"document.getElementById('form').submit();\">"
			"This page will automatically redirect you to your identity provider.  "
			"If you are not immediately redirected, click the submit button below."
			"<form id=\"form\" action=\"" + url + "\" method=\"post\">" + inputs + "<input type=\"submit\" value=\"submit\">"      
			"</form></body></html>";

		// return HTTP_UNAUTHORIZED so that no further modules can produce output
		return http_sendstring(r, result, HTTP_UNAUTHORIZED);
	};

	int http_redirect(request_rec *r, string location) {
		// Because IE is retarded, we have to do a form post if the URL is too big (over 2048 characters)
		if(location.size() > 2000) {
			debug("Redirecting via POST to: " + location);
			return send_form_post(r, location);
		} else {
			debug("Redirecting via HTTP_MOVED_TEMPORARILY to: " + location);
			apr_table_set(r->headers_out, "Location", location.c_str());
			apr_table_setn(r->err_headers_out, "Cache-Control", "no-cache");
			return HTTP_MOVED_TEMPORARILY;
		}
	};

	int show_html_redirect_page(request_rec *r, string source_location) {
		string result = 
			"<HTML>\n"
			"<HEAD>\n"
			"<TITLE></TITLE>\n"
			"<SCRIPT language=javascript>\n"
			"<!--\n"
			"var uri = window.location.href;\n"
			"var redirect_uri = uri.replace(\""+source_location+"redirect#\", \""+source_location+"?\");\n"
			"window.location.href = redirect_uri;\n"
			"-->\n"
			"</SCRIPT>\n"
			"</HEAD>\n"
			"<BODY>\n"
			"</BODY>\n"
			"</HTML>\n";

		// return HTTP_UNAUTHORIZED so that no further modules can produce output
		return http_sendstring(r, result, HTTP_MOVED_TEMPORARILY);
	};

	int show_html_error_message(request_rec *r, string name, string msg) {
		opkele::params_t params;
		if(r->args != NULL)
			params = parse_query_string(string(r->args));
		string identity = params.has_param("openid_identifier") ? params.get_param("openid_identifier") : "";
		remove_openid_vars(params);
		map<string,string>::iterator iter;
		string args = "";
		string key, value;
		for(iter = params.begin(); iter != params.end(); iter++) {
			key = html_escape(iter->first);
			value = html_escape(iter->second);
			args += "<input type=\"hidden\" name=\"" + key + "\" value = \"" + value + "\" />";
		}
		string result = 
			"<HTML><HEAD><TITLE>Error on OX</TITLE></HEAD>"
			"<BODY><H1>Protected Location</H1>"
			"<span style=\"font-size:20px;font-weight:bold\">Error : </span>"
			"<span style=\"font-size:18px;font-weight:bold\">"
			+ (msg.empty()?"":msg) +
			"</span></br></br>You don't have permission to access <B>"
			+ (name.empty()?"":name) +
			"</B> on this server.<P><HR>"
			"<ADDRESS>protected by mod_ox 0.1</ADDRESS>"
			"</BODY></HTML>";

		// return HTTP_UNAUTHORIZED so that no further modules can produce output
		return http_sendstring(r, result, HTTP_UNAUTHORIZED);
	};

	void get_session_id(request_rec *r, string cookie_name, string& session_key, string& session_value) {
		const char * cookies_c = apr_table_get(r->headers_in, "Cookie");
		if(cookies_c == NULL)
			return;
		string cookies(cookies_c);
		//vector<string> pairs = explode(cookies, ";");
		char cookie[4096];
		char * pairs;
		strcpy(cookie, cookies.c_str());
		pairs = strtok (cookie,";");
		while (pairs != NULL)
		{
			while(pairs[0] == ' ') 
				pairs++;
			if(!strncmp(pairs, cookie_name.c_str(), strlen(cookie_name.c_str())-1)) {
				char *pair;
				pair = strtok (pairs,"=");
				session_key = pair;
				session_value = strtok (NULL, "=");
				return;
			}
			pairs = strtok (NULL, ";");
		}
/*
		for(string::size_type i = 0; i < pairs.size(); i++) {
			debug("cookie sent by client3: \""+pairs[i]+"\"");
			vector<string> pair = explode(pairs[i], "=");
			if(pair.size() == 2) {
				string key = pair[0];
				strip(key);
				string value = pair[1];
				strip(value);
				//debug("cookie sent by client: \""+key+"\"=\""+value+"\"");
				if(!strncmp(key.c_str(), cookie_name.c_str(), strlen(cookie_name.c_str())-1)) {
					session_key = pair[0];
					session_value = pair[1];
					return;
				}
			}
		}
		debug("cookie sent by client4: \""+cookies+"\"");
	*/
	};

	// get the base directory of the url
	void base_dir(string path, string& s) {
		// guaranteed that path will at least be "/" - but just to be safe... 
		if(path.size() == 0)
			return;
		string::size_type q = path.find('?', 0);
		size_t i;
		if(q != string::npos)
			i = path.find_last_of('/', q);
		else
			i = path.find_last_of('/');
		s = path.substr(0, i+1);
	};

	// assuming the url given will begin with http(s):// - worst case, return blank string 
	string get_queryless_url(string url) {
		if(url.size() < 8)
			return "";
		if(url.find("http://",0) != string::npos || url.find("https://",0) != string::npos) {
			string::size_type last = url.find('?', 8);
			if(last != string::npos)
				return url.substr(0, last);
			return url;
		}
		return "";
	};

	void remove_openid_vars(params_t& params) {
		map<string,string>::iterator iter, iter_next;
		for(iter = params.begin(); iter != params.end(); ) {
			iter_next = iter;
			++iter_next;
			string param_key(iter->first);
			// if starts with openid. or modox. (for the nonce) or openid_identifier (the login) remove it
			if((param_key.substr(0, 7) == "openid." || param_key.substr(0, 14) == "modox." || param_key == "openid_identifier")) {
				params.erase(iter); // invalidates iter, but its successor iter_next is still valid
			}
			iter = iter_next;
		}
	};

	void get_extension_params(params_t& extparams, params_t& params) {
		map<string,string>::iterator iter;
		extparams.reset_fields();
		for(iter = params.begin(); iter != params.end(); iter++) {
			string param_key(iter->first);
			vector<string> parts = explode(param_key, ".");
			// if there is more than one "." in the param name then we're 
			// dealing with an extension parameter
			if(parts.size() > 2)
				extparams[param_key] = params[param_key];
		}
	};

	// for each key/value in params_one, set params_two[key] = value
	void merge_params(params_t& params_one, params_t& params_two) {
		map<string,string>::iterator iter;
		for(iter = params_one.begin(); iter != params_one.end(); iter++) {
			string param_key(iter->first);
			params_two[param_key] = params_one[param_key];
		}
	};

	// This isn't a true html_escape function, but rather escapes just enough to get by for
	// quoted values - <blah name="stuff to be escaped">  
	string html_escape(string s) {
		s = str_replace("&", "&amp;", s);
		s = str_replace("'", "&#39;", s);
		s = str_replace("\"", "&quot;", s);
		s = str_replace("<", "&lt;", s);
		s = str_replace(">", "&gt;", s);
		return s;
	};

#define ishex(in) ((in >= 'a' && in <= 'f') || \
	(in >= 'A' && in <= 'F') || \
	(in >= '0' && in <= '9'))

	char *unescape(const char *string, int length)
	{
		int alloc = (length?length:(int)strlen(string))+1;
		char *ns = (char *)malloc(alloc);
		unsigned char in;
		int strindex=0;
		long hex;

		if( !ns )
			return NULL;

		while(--alloc > 0) {
			in = *string;
			if(('%' == in) && ishex(string[1]) && ishex(string[2])) {
				/* this is two hexadecimal digits following a '%' */
				char hexstr[3];
				char *ptr;
				hexstr[0] = string[1];
				hexstr[1] = string[2];
				hexstr[2] = 0;

				hex = strtol(hexstr, &ptr, 16);

				in = (unsigned char)hex; /* this long is never bigger than 255 anyway */
				string+=2;
				alloc-=2;
			}

			ns[strindex++] = in;
			string++;
		}
		ns[strindex]=0; /* terminate it */
		return ns;
	}

	/* For operating systems/environments that use different malloc/free
	ssystems for the app and for this library, we provide a free that uses
	the library's memory system */
	void unescape_free(void *p)
	{
		if(p)
			free(p);
	};


	string url_decode(const string& str) {
		// if +'s aren't replaced with %20's then curl won't unescape to spaces properly
		string url = str_replace("+", "%20", str);

		char * t = unescape(url.c_str(), url.length());
		if(!t)
			throw failed_conversion(OPKELE_CP_ "failed to curl_unescape()");

		string rv(t);
		unescape_free(t);
		return rv;
	};

	params_t parse_query_string(const string& str) {
		params_t p;
		if(str.size() == 0) return p;

		vector<string> pairs = explode(str, "&");
		for(unsigned int i=0; i < pairs.size(); i++) {
			string::size_type loc = pairs[i].find( "=", 0 );
			// if loc found and loc isn't last char in string 
			if( loc != string::npos && loc != str.size()-1) {
				string key = url_decode(pairs[i].substr(0, loc));
				string value = url_decode(pairs[i].substr(loc+1));
				p[key] = value;
			}
		}
		return p;
	};

	void make_cookie_value(string& cookie_value, const string& name, const string& session_id, const string& path, int cookie_lifespan, bool secure_cookie) {
		cookie_value = name + "=" + session_id + "; path=" + path + "; HttpOnly";
		if(cookie_lifespan != 0) {
			time_t t;
			t = time(NULL) + cookie_lifespan;
			struct tm *tmp;
			tmp = gmtime(&t);
			char expires[200];
			strftime(expires, sizeof(expires), "%a, %d-%b-%Y %H:%M:%S GMT", tmp);
			cookie_value += "; expires=" + string(expires);
		}
		if (secure_cookie) {
			cookie_value += "; Secure";
		}
	};

	// Get the post query string from a HTTP POST
	bool get_post_data(request_rec *r, string& qs) {
		// check to make sure the right content type was used
		const char *type = apr_table_get(r->headers_in, "Content-Type");
		if (strcasecmp(type, DEFAULT_POST_ENCTYPE) != 0)
			return false;

		apr_bucket_brigade *bb = apr_brigade_create(r->pool, r->connection->bucket_alloc);
		apr_status_t ret;
		int seen_eos, child_stopped_reading;
		seen_eos = child_stopped_reading = 0; 
		char *query_string = NULL;

		do { 
			ret = ap_get_brigade(r->input_filters, bb, AP_MODE_READBYTES, APR_BLOCK_READ, 8192); 
			if(ret != APR_SUCCESS)
				return false;

			apr_bucket *bucket; 
			for(bucket=APR_BRIGADE_FIRST(bb); bucket!=APR_BRIGADE_SENTINEL(bb); bucket=APR_BUCKET_NEXT(bucket)) { 
				apr_size_t len; 
				const char *data; 
				if(APR_BUCKET_IS_EOS(bucket)) { 
					seen_eos = 1; 
					break; 
				}
				if(APR_BUCKET_IS_FLUSH(bucket)) 
					continue;
				if(child_stopped_reading)
					continue; 

				ret = apr_bucket_read(bucket, &data, &len, APR_BLOCK_READ); 
				if(ret != APR_SUCCESS) {
					child_stopped_reading = 1;
				} else {
					if (query_string == NULL) 
						query_string = apr_pstrndup(r->pool, data, len);
					else 
						query_string = apr_pstrcat(r->pool, query_string, apr_pstrndup(r->pool, data, len), NULL);
				}
			} 
			apr_brigade_cleanup(bb); 
		} while (!seen_eos); 

		qs = (query_string == NULL) ? "" : string(query_string);
		return true; 
	};

	// Get request parameters - whether POST or GET
	void get_request_params(request_rec *r, params_t& params) {
		string query;
	
		if(r->method_number == M_GET && r->args != NULL) {
			debug("Request GET params: " + string(r->args));
			params = parse_query_string(string(r->args));
		} else if(r->method_number == M_POST && get_post_data(r, query)) {
			debug("Request POST params: " + query);
			params = parse_query_string(query);
		}
	};

}
