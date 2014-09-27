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

#include <opk_exception.h>

#ifdef NDEBUG

#define D_(x)		((void)0)
#define DOUT_(x)	((void)0)

#else /* NDEBUG */

#define D_(x)		x
#include <iostream>
#define DOUT_(x)	std::clog << x << std::endl

#endif /* NDEBUG */

namespace opkele {

#   ifndef OPKELE_HAVE_KONFORKA

    exception::exception(const string& w)
	: _what(w)
    {
	DOUT_("throwing exception(\""<<w<<"\")");
    }

    exception::~exception() throw() {
    }
    const char *exception::what() const throw() {
	return _what.c_str();
    }

#   else
    
    exception::exception(const string& fi,const string& fu,int l,const string& w)
	: konforka::exception(fi,fu,l,w)
    {
	DOUT_("throwing exception(\""<<w<<"\")");
	DOUT_(" from "<<fi<<':'<<fu<<':'<<l);
    }

#   endif
    exception_tidy::exception_tidy(OPKELE_E_PARS)
	: exception(OPKELE_E_CONS), _rc(0) { }
    exception_tidy::exception_tidy(OPKELE_E_PARS,int r)
	: exception(OPKELE_E_CONS),
	_rc(r) { }

}
