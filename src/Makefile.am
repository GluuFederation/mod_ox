noinst_LTLIBRARIES = libmodox.la
noinst_DATA = mod_ox.la

INCLUDES = ${APACHE_CFLAGS}
AM_LDFLAGS = ${APR_LDFLAGS}

libmodox_la_SOURCES = mod_ox.cpp memcache.cpp storage.cpp \
	json_array.cpp json_boolean.cpp json_main.cpp json_null.cpp json_number.cpp json_object.cpp json_serializer.cpp json_string.cpp json_value.cpp json_parser.cpp \
	oidc_http.cpp oidc_utils.cpp \
	opk_exception.cpp opk_fields.cpp opk_message.cpp opk_params.cpp opk_util.cpp \
	oxd_client.cpp oxd_main.cpp \
	proc_connect.cpp proc_uma.cpp proc_saml.cpp

AM_CXXFLAGS = -Wall

if NITPICK
AM_CXXFLAGS += -Wextra -Wundef -Wshadow -Wunsafe-loop-optimizations -Wconversion -Wmissing-format-attribute
AM_CXXFLAGS += -Wredundant-decls -ansi -Wmissing-noreturn
endif

if DEBUG
AM_CXXFLAGS += -DDEBUG
endif

install-exec-local:
	${APXS} -i -a -n 'ox' mod_ox.la

mod_ox.la: libmodox.la
	${APXS} -lstdc++ -lcurl -c -o $@ $< ${APACHE_CFLAGS}
