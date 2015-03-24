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

#include <cstdlib>
#include <cstdio>
#include <ctime>
#include <cerrno>

#include "json_number.h"
#include "json_boolean.h"
#include "json_string.h"

#include "json_serializer.h"
#include "json_parser.h"

#include "json_main.h"

#define BUF_SIZE 8192  // BUF_SIZE CAN BE ANY.
#define MAX_LEVEL	256

static JSONValue* jsonRoot = NULL;
int libjson_init( char* in_str, int in_len )
{
	size_t pos;
	size_t len;
	char buf[ BUF_SIZE ];

	if (jsonRoot != NULL)
		delete jsonRoot;
	
	jsonRoot = NULL;
	len = in_len;
	if (len > BUF_SIZE)
		return RET_FAILURE;	

	memcpy(buf, in_str, len);

	if( len > 0 && jsonRoot == NULL )
	{
		if( !JSONValue::create( buf, len, jsonRoot ) )
		{
			return RET_FAILURE;
		}
		else if( jsonRoot == NULL )
			return RET_FAILURE;
	}

	pos = jsonRoot->parse( buf, len );
	switch( jsonRoot->status )
	{
	case JSONValue::COMPLETE:
		break;

	case JSONValue::ERROR:
		delete jsonRoot;
		jsonRoot = NULL;
		return RET_FAILURE;
	}

	if( jsonRoot->status == JSONValue::INCOMPLETE )
	{
		delete jsonRoot;
		jsonRoot = NULL;
		return RET_FAILURE;
	}

	if( jsonRoot->type != JSONValue::Object )
	{
		delete jsonRoot;
		jsonRoot = NULL;
		return RET_FAILURE;
	}

	return RET_SUCCESS;
}

int libjson_serialize( char* out_str, int out_len )
{
	size_t pos;
	size_t len;
	char buf[ BUF_SIZE ];

	if (jsonRoot == NULL)
		return RET_FAILURE;

	pos = 0; len = 0;
	if( jsonRoot->type == JSONValue::Object )
	{
		JSONObjectSerializer encoder;
		encoder.open( jsonRoot );
		while( (pos = encoder.encode( buf, BUF_SIZE )) > 0 )
		{
			if ( (len+pos) > (size_t)out_len )
				return RET_FAILURE;

			memcpy(&out_str[len], buf, pos);
			len += pos;
			out_str[len] = 0;
		}
	}
	else if( jsonRoot->type == JSONValue::Array )
	{
		JSONArraySerializer encoder;
		encoder.open( jsonRoot );
		while( (pos = encoder.encode( buf, BUF_SIZE )) > 0 )
		{
			if ( (len+pos) > (size_t)out_len )
				return RET_FAILURE;

			memcpy(&out_str[len], buf, pos);
			len += pos;
			out_str[len] = 0;
		}
	}

	return (int)len;
}

int libjson_getKeyValue(char *in_key_str, char *out_value, int out_max_len)
{
	if (jsonRoot == NULL)
		return RET_FAILURE;

	char *ptr;
	const JSONValue* result = jsonRoot;
	const JSONValue* preResult;
	const JSONString* tempjsonstr;
	const JSONArray* tempjsonarray;
	char key_str[BUF_SIZE];
	
	strcpy(key_str, in_key_str);
	ptr = strtok(key_str, ".");
	while( (ptr != NULL) && (result != NULL) )
	{
		int arrayNum = -1;
		JSONString keyword(ptr);
		
		preResult = result;
		result = static_cast<const JSONObject*>(result)->get(&keyword);
		if (result == NULL)
		{
			if (ptr[strlen(ptr)-1] == ']')
			{
				for (size_t i=(strlen(ptr)-2); i>0; i--)
				{
					if (ptr[i] == '[')
					{
						ptr[i] = 0;
						JSONString keyword1(ptr);
						result = static_cast<const JSONObject*>(preResult)->get(&keyword1);

						if ((result == NULL) || (result->type != JSONValue::Array))
							return RET_FAILURE;

						ptr[i] = '[';
						ptr[strlen(ptr)-1] = 0;
						errno = 0;
						arrayNum = atoi(&ptr[i+1]);
						if (errno != 0)
							return RET_FAILURE;
						else
							break;
					}
				}
			}
			else
				return RET_FAILURE;
		}

		ptr = strtok(NULL, ".");
		switch (result->type)
		{
		case JSONValue::String:
			tempjsonstr = static_cast<const JSONString*>(result);
			strncpy(out_value, tempjsonstr->get(), tempjsonstr->len());
			out_value[tempjsonstr->len()] = 0;

			if (ptr == NULL)
				return RET_SUCCESS;
			else
				return RET_FAILURE;
			break;
		case JSONValue::Array:
			if (arrayNum >= 0)
			{
				tempjsonarray = static_cast<const JSONArray*>(result);
				result = static_cast<const JSONValue*>(tempjsonarray->get(arrayNum));
				if ((ptr == NULL) && (result != NULL))
				{
					if (result->type == JSONValue::String)
					{
						tempjsonstr = static_cast<const JSONString*>(result);
						strncpy(out_value, tempjsonstr->get(), tempjsonstr->len());
						out_value[tempjsonstr->len()] = 0;

						return RET_SUCCESS;
					}
				}

				break;
			}
			return RET_FAILURE;
		case JSONValue::Object:
			break;
		default:
			return RET_FAILURE;
		}
	}
	
	return RET_FAILURE;
}

int libjson_getKeyValue(char *in_key_str, double *out_value)
{
	if (jsonRoot == NULL)
		return RET_FAILURE;

	char *ptr;
	const JSONValue *result = jsonRoot;
	const JSONValue* preResult;
	const JSONNumber* tempjsonnum;
	const JSONArray* tempjsonarray;
	char key_str[BUF_SIZE];

	strcpy(key_str, in_key_str);
	ptr = strtok(key_str, ".");
	while( (ptr != NULL) && (result != NULL) )
	{
		int arrayNum = -1;
		JSONString keyword(ptr);

		preResult = result;
		result = static_cast<const JSONObject*>(result)->get(&keyword);
		if (result == NULL)
		{
			if (ptr[strlen(ptr)-1] == ']')
			{
				for (size_t i=(strlen(ptr)-2); i>0; i--)
				{
					if (ptr[i] == '[')
					{
						ptr[i] = 0;
						JSONString keyword1(ptr);
						result = static_cast<const JSONObject*>(preResult)->get(&keyword1);

						if ((result == NULL) || (result->type != JSONValue::Array))
							return RET_FAILURE;

						ptr[i] = '[';
						ptr[strlen(ptr)-1] = 0;
						errno = 0;
						arrayNum = atoi(&ptr[i+1]);
						if (errno != 0)
							return RET_FAILURE;
						else
							break;
					}
				}
			}
			else
				return RET_FAILURE;
		}

		ptr = strtok(NULL, ".");
		switch (result->type)
		{
		case JSONValue::Number:
			tempjsonnum = static_cast<const JSONNumber*>(result);
			*out_value = tempjsonnum->get();

			if (ptr == NULL)
				return RET_SUCCESS;
			else
				return RET_FAILURE;

			break;
		case JSONValue::Array:
			if (arrayNum >= 0)
			{
				tempjsonarray = static_cast<const JSONArray*>(result);
				result = static_cast<const JSONValue*>(tempjsonarray->get(arrayNum));
				if ((ptr == NULL) && (result != NULL))
				{
					if (result->type == JSONValue::Number)
					{
						tempjsonnum = static_cast<const JSONNumber*>(result);
						*out_value = tempjsonnum->get();
						
						return RET_SUCCESS;
					}
				}
				break;
			}
			return RET_FAILURE;
		case JSONValue::Object:
			break;
		default:
			return RET_FAILURE;
		}
	}

	return RET_FAILURE;
}

int libjson_getKeyValue(char *in_key_str, bool *out_value)
{
	if (jsonRoot == NULL)
		return RET_FAILURE;

	char *ptr;
	const JSONValue *result = jsonRoot;
	const JSONValue* preResult;
	const JSONBoolean* tempjsonbool;
	const JSONArray* tempjsonarray;
	char key_str[BUF_SIZE];

	strcpy(key_str, in_key_str);
	ptr = strtok(key_str, ".");
	while( (ptr != NULL) && (result != NULL) )
	{
		int arrayNum = -1;
		JSONString keyword(ptr);

		preResult = result;
		result = static_cast<const JSONObject*>(result)->get(&keyword);
		if (result == NULL)
		{
			if (ptr[strlen(ptr)-1] == ']')
			{
				for (size_t i=(strlen(ptr)-2); i>0; i--)
				{
					if (ptr[i] == '[')
					{
						ptr[i] = 0;
						JSONString keyword1(ptr);
						result = static_cast<const JSONObject*>(preResult)->get(&keyword1);

						if ((result == NULL) || (result->type != JSONValue::Array))
							return RET_FAILURE;

						ptr[i] = '[';
						ptr[strlen(ptr)-1] = 0;
						errno = 0;
						arrayNum = atoi(&ptr[i+1]);
						if (errno != 0)
							return RET_FAILURE;
						else
							break;
					}
				}
			}
			else
				return RET_FAILURE;
		}

		ptr = strtok(NULL, ".");
		switch (result->type)
		{
		case JSONValue::Boolean:
			tempjsonbool = static_cast<const JSONBoolean*>(result);
			*out_value = tempjsonbool->get();

			if (ptr == NULL)
				return RET_SUCCESS;
			else
				return RET_FAILURE;

			break;
		case JSONValue::Array:
			if (arrayNum >= 0)
			{
				tempjsonarray = static_cast<const JSONArray*>(result);
				result = static_cast<const JSONValue*>(tempjsonarray->get(arrayNum));
				if ((ptr == NULL) && (result != NULL))
				{
					if (result->type == JSONValue::Boolean)
					{
						tempjsonbool = static_cast<const JSONBoolean*>(result);
						*out_value = tempjsonbool->get();

						return RET_SUCCESS;
					}
				}

				break;
			}
			return RET_FAILURE;
		case JSONValue::Object:
			break;
		default:
			return RET_FAILURE;
		}
	}

	return RET_FAILURE;
}

int libjson_getArrayNum(char *in_key_str)
{
	if (jsonRoot == NULL)
		return RET_FAILURE;

	char *ptr;
	const JSONValue *result = jsonRoot;
	const JSONValue* preResult;
	const JSONArray *tempjsonarray;
	char key_str[BUF_SIZE];

	strcpy(key_str, in_key_str);
	ptr = strtok(key_str, ".");
	while( (ptr != NULL) && (result != NULL) )
	{
		int arrayNum = -1;
		JSONString keyword(ptr);

		preResult = result;
		result = static_cast<const JSONObject*>(result)->get(&keyword);
		if (result == NULL)
		{
			if (ptr[strlen(ptr)-1] == ']')
			{
				for (size_t i=(strlen(ptr)-2); i>0; i--)
				{
					if (ptr[i] == '[')
					{
						ptr[i] = 0;
						JSONString keyword1(ptr);
						result = static_cast<const JSONObject*>(preResult)->get(&keyword1);

						if ((result == NULL) || (result->type != JSONValue::Array))
							return -1;

						ptr[i] = '[';
						ptr[strlen(ptr)-1] = 0;
						errno = 0;
						arrayNum = atoi(&ptr[i+1]);
						if (errno != 0)
							return -1;
						else
							break;
					}
				}
			}
			else
				return -1;
		}

		ptr = strtok(NULL, ".");
		switch (result->type)
		{
		case JSONValue::Array:
			tempjsonarray = static_cast<const JSONArray*>(result);
			if (ptr == NULL)
			{
				return (int)(tempjsonarray->getcount());
			}
			else if (arrayNum >= 0)
			{
				result = static_cast<const JSONValue*>(tempjsonarray->get(arrayNum));
				break;
			}
			return -1;
		case JSONValue::Object:
			break;
		default:
			return -1;
		}
	}

	return -1;
}

int libjson_deserialize(const char *in_str, int in_size, char *out_str, int out_size)
{
	return decode_JSON_string(in_str, in_size, out_str, out_size);
}