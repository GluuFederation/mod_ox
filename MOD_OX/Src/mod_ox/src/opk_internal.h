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

#ifndef __OPKELE_UTIL_INTERNAL_H
#define __OPKELE_UTIL_INTERNAL_H

//#include <openssl/bn.h>
//#include <openssl/dh.h>
//#include <opkele/types.h>

namespace opkele {
    namespace util {

	/**
	 * Convenience class encapsulating SSL BIGNUM object for the purpose of
	 * automatical freeing.
	 */
/*
	class bignum_t {
	    public:
		BIGNUM *_bn;

		bignum_t() : _bn(0) { }
		bignum_t(BIGNUM *bn) : _bn(bn) { }
		~bignum_t() throw() { if(_bn) BN_free(_bn); }
		
		bignum_t& operator=(BIGNUM *bn) { if(_bn) BN_free(_bn); _bn = bn; return *this; }

		operator const BIGNUM*(void) const { return _bn; }
		operator BIGNUM*(void) { return _bn; }
	};
*/
	/**
	 * Convenience clas encapsulating SSL DH object for the purpose of
	 * automatic freeing.
	 */
/*
	class dh_t {
	    public:
		DH *_dh;
		
		dh_t() : _dh(0) { }
		dh_t(DH *dh) : _dh(dh) { }
		~dh_t() throw() { if(_dh) DH_free(_dh); }

		dh_t& operator=(DH *dh) { if(_dh) DH_free(_dh); _dh = dh; return *this; }

		operator const DH*(void) const { return _dh; }
		operator DH*(void) { return _dh; }

		DH* operator->() { return _dh; }
		const DH* operator->() const { return _dh; }
	};
*/
	/**
	 * Convert base64-encoded SSL BIGNUM to internal representation.
	 * @param b64 base64-encoded number
	 * @return SSL BIGNUM
	 * @throw failed_conversion in case of error
	 */
//	BIGNUM *base64_to_bignum(const string& b64);
	/**
	 * Convert decimal representation to SSL BIGNUM.
	 * @param dec decimal representation
	 * @return resulting BIGNUM
	 * @throw failed_conversion in case of error
	 */
//	BIGNUM *dec_to_bignum(const string& dec);
	/**
	 * Convert SSL BIGNUM data to base64 encoded string.
	 * @param bn BIGNUM
	 * @return base64encoded string
	 */
//	string bignum_to_base64(const BIGNUM *bn);

//	string abi_demangle(const char* mn);
/*
	class change_mode_message_proxy : public basic_openid_message {
	    public:
		const basic_openid_message& x;
		const string& mode;

		change_mode_message_proxy(const basic_openid_message& xx,const string& m) : x(xx), mode(m) { }

		bool has_field(const string& n) const { return x.has_field(n); }
		const string& get_field(const string& n) const {
		    return (n=="mode")?mode:x.get_field(n); }
		bool has_ns(const string& uri) const {return x.has_ns(uri); }
		string get_ns(const string& uri) const { return x.get_ns(uri); }
		fields_iterator fields_begin() const {
		    return x.fields_begin(); }
		fields_iterator fields_end() const {
		    return x.fields_end(); }
	};
*/
    }
}

#endif /* __OPKELE_UTIL_INTERNAL_H */
