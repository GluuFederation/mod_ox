#include <errno.h>
#include <cassert>
#include <cctype>
#include <stdio.h>
#include <cstring>
#include <vector>
#include <string>
#include <stack>
#include <algorithm>
#include <opk_util.h>
#include <opk_exception.h>

#ifdef HAVE_DEMANGLE
# include <cxxabi.h>
#endif

namespace opkele {
    using namespace std;

    namespace util {

	unsigned char base64_alph[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";
	/* to be sure of hex-values
	0     1     2     3     4     5     6     7     8     9     A     B     C     D     E     F
	0000  0001  0010  0011  0100  0101  0110  0111  1000  1001  1010  1011  1100  1101  1110  1111
	*/
	int
	encode_base64(const unsigned char *in, long isize, unsigned char **out, long *osize)
	{
        long l, o_pos = 0, len;
        unsigned char t;
        long line_size = 0;

        len = (long) ((double) isize * 1.33) + 4;
        len += ((len / 76) * 2) + 2;
        *out = (unsigned char *)malloc(len);
        if (*out == NULL)
			return -1;

        for (l = 0; l < isize; l += 3)
        {
            if (l < (isize - 2))
            {
                t = (in[l] & 0xfc) >> 2;
                (*out)[o_pos++] = base64_alph[t];
                t = ((in[l] & 0x03) << 4) | ((in[l + 1] & 0xf0) >> 4);
                (*out)[o_pos++] = base64_alph[t];
                t = ((in[l + 1] & 0x0f) << 2) | ((in[l + 2] & 0xc0) >> 6);
                (*out)[o_pos++] = base64_alph[t];
                t = in[l + 2] & 0x3f;
                (*out)[o_pos++] = base64_alph[t];
            }
            else if (l < (isize - 1))
            {
                t = (in[l] & 0xfc) >> 2;
                (*out)[o_pos++] = base64_alph[t];
                t = ((in[l] & 0x03) << 4) | ((in[l + 1] & 0xf0) >> 4);
                (*out)[o_pos++] = base64_alph[t];
                t = (in[l + 1] & 0x0f) << 2;
                (*out)[o_pos++] = base64_alph[t];
                (*out)[o_pos++] = '=';
            }
            else
            {
                t = (in[l] & 0xfc) >> 2;
                (*out)[o_pos++] = base64_alph[t];
                t = (in[l] & 0x03) << 4;
                (*out)[o_pos++] = base64_alph[t];
                (*out)[o_pos++] = '=';
                (*out)[o_pos++] = '=';
            }
            line_size += 4;

            if (line_size >= 76)
            {
                (*out)[o_pos++] = '\n'; /* libxml2 has problems with CRLF */
                line_size = 0;
            }
        }
        (*out)[o_pos] = '\0';   /* being save if osize will be ignored */
        *osize = o_pos;
        *out = (unsigned char *)realloc(*out, *osize + 1);

        return 0;
	} /* encode_base64() */

	int
	decode_base64(const unsigned char *in, long isize, unsigned char **out, long *osize, long max_size)
	{
        long l;
        long o_pos = 0;

        unsigned char decode_alph[255];

        for (l = 0; l < 64; l++)
			decode_alph[base64_alph[l]] = (unsigned char)l;

        *out = (unsigned char *)malloc(isize);

        l = 0;
        for (;;)
        {
            if ((max_size != -1) && (o_pos >= max_size))
				break;  /* we have all needed data */

            if ((l + 3) >= isize)
				break;

            if ((in[l] == 0x0A) || (in[l] == 0x0D) || (in[l] == ' '))
            {
				l++;
				continue;
            }

            (*out)[o_pos++] = (decode_alph[in[l]] << 2) | ((decode_alph[in[l + 1]] & 0xf0) >> 4);
            if (in[l + 2] != '=')
				(*out)[o_pos++] = ((decode_alph[in[l + 1]] & 0x0f) << 4) | ((decode_alph[in[l + 2]] & 0xfc) >> 2);

            if (in[l + 3] != '=')
				(*out)[o_pos++] = ((decode_alph[in[l + 2]] & 0x03) << 6) | decode_alph[in[l + 3]];

            l += 4;
        }

        *osize = o_pos;
        *out = (unsigned char *)realloc(*out, *osize);

        return 0;
	} /* decode_base64() */

	static inline bool isrfc3986unreserved(int c) {
	    if(c<'-') return false;
	    if(c<='.') return true;
	    if(c<'0') return false; if(c<='9') return true;
	    if(c<'A') return false; if(c<='Z') return true;
	    if(c<'_') return false;
	    if(c=='_') return true;
	    if(c<'a') return false; if(c<='z') return true;
	    if(c=='~') return true;
	    return false;
	}

	struct __url_encoder : public unary_function<char,void> {
	    public:
		string& rv;

		__url_encoder(string& r) : rv(r) { }

		result_type operator()(argument_type c) {
		    if(isrfc3986unreserved(c))
			rv += c;
		    else{
			char tmp[4];
			sprintf(tmp,"%%%02X",
				(c&0xff));
			rv += tmp;
		    }
		}
	};

	string url_encode(const string& str) {
	    string rv;
	    for_each(str.begin(),str.end(),
		    __url_encoder(rv));
	    return rv;
	}

	string attr_escape(const string& str) {
	    static const char *unsafechars = "<>&\n\"'";
	    string rv;
	    string::size_type p=0;
	    while(true) {
		string::size_type us = str.find_first_of(unsafechars,p);
		if(us==string::npos) {
		    if(p!=str.length())
			rv.append(str,p,str.length()-p);
		    return rv;
		}
		rv.append(str,p,us-p);
		rv += "&#";
		rv += long_to_string((long)str[us]);
		rv += ';';
		p = us+1;
	    }
	}

	string long_to_string(long l) {
	    char rv[32];
	    int r=sprintf(rv,"%ld",l);
	    if(r<0 || r>=(int)sizeof(rv))
		throw failed_conversion(OPKELE_CP_ "failed to snprintf()");
	    return rv;
	}

	long string_to_long(const string& s) {
	    char *endptr = 0;
	    long rv = strtol(s.c_str(),&endptr,10);
	    if((!endptr) || endptr==s.c_str())
		throw failed_conversion(OPKELE_CP_ "failed to strtol()");
	    return rv;
	}
  }

}
