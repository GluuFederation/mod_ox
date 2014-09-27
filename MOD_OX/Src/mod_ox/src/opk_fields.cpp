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

#include <opk_types.h>
#include <opk_exception.h>
#include <opk_util.h>
#include <algorithm>

namespace opkele {
    using std::for_each;
    using std::unary_function;

    struct __om_copier : public unary_function<const string&,void> {
	public:
	    const basic_fields& from;
	    basic_fields& to;

	    __om_copier(basic_fields& t,const basic_fields& f)
		: from(f), to(t) { }

	    result_type operator()(argument_type f) {
		to.set_field(f,from.get_field(f)); }
    };

    basic_fields::basic_fields(const basic_fields& x) {
	x.copy_to(*this);
    }
    void basic_fields::copy_to(basic_fields& x) const {
	x.reset_fields();
	for_each(fields_begin(),fields_end(),
		__om_copier(x,*this) );
    }
    void basic_fields::append_to(basic_fields& x) const {
	for_each(fields_begin(),fields_end(),
		__om_copier(x,*this) );
    }

    struct __om_query_builder : public unary_function<const string&,void> {
	public:
	    const basic_fields& om;
	    bool first;
	    string& rv;
	    const char *pfx;

	    __om_query_builder(const char *p,string& r,const basic_fields& m)
		: om(m), first(true), rv(r), pfx(p) {
		    for_each(om.fields_begin(),om.fields_end(),*this);
		}
	    __om_query_builder(const char *p,string& r,const basic_fields& m,const string& u)
		: om(m), first(true), rv(r), pfx(p) {
		    rv = u;
		    if(rv.find('?')==string::npos)
			rv += '?';
		    else
			first = false;
		    for_each(om.fields_begin(),om.fields_end(),*this);
		}

	    result_type operator()(argument_type f) {
		if(first)
		    first = false;
		else
		    rv += '&';
		if(pfx) rv += pfx;
		rv+= f;
		rv += '=';
		rv += util::url_encode(om.get_field(f));
	    }
    };

    string basic_fields::append_query(const string& url,const char *pfx) const {
	string rv;
	return __om_query_builder(pfx,rv,*this,url).rv;
    }
    string basic_fields::query_string(const char *pfx) const {
	string rv;
	return __om_query_builder(pfx,rv,*this).rv;
    }

    void basic_fields::reset_fields() {
	throw not_implemented(OPKELE_CP_ "reset_fields() not implemented");
    }
    void basic_fields::set_field(const string&,const string&) {
	throw not_implemented(OPKELE_CP_ "set_field() not implemented");
    }
    void basic_fields::reset_field(const string&) {
	throw not_implemented(OPKELE_CP_ "reset_field() not implemented");
    }


}
