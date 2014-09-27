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

#ifndef __LIBJSON_H_
#define __LIBJSON_H__

#define RET_SUCCESS    0
#define RET_FAILURE    -1

int libjson_init( char* in_str, int in_len );
int libjson_serialize( char* out_str, int out_len );
int libjson_getKeyValue(char *in_key_str, char *out_value, int out_max_len);
int libjson_getKeyValue(char *in_key_str, double *out_value);
int libjson_getKeyValue(char *in_key_str, bool *out_value);
int libjson_getArrayNum(char *in_key_str);
int libjson_deserialize(const char *in_str, int in_size, char *out_str, int out_size);

#endif /*__LIBJSON_H__*/