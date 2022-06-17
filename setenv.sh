#!/bin/sh
#
# Set up environment variables for general build tool to operate
#
if ! [ -f ./setenv.sh ]; then
	echo "Need to source from the setenv.sh directory" >&2
	return 0
fi

export PORT_ROOT="${PWD}"
export PORT_TYPE="TARBALL"

export PORT_TARBALL_URL="https://www.openssl.org/source/openssl-1.1.1o.tar.gz"
export PORT_TARBALL_DEPS="curl git gzip make m4 perl"

export PORT_GIT_URL="https://github.com/openssl/openssl"
export PORT_GIT_DEPS="git make m4 perl autoconf automake help2man makeinfo xz"

export PORT_EXTRA_CFLAGS=""
export PORT_EXTRA_LDFLAGS=""

if [ "${PORT_TYPE}x" = "TARBALLx" ]; then
	export PORT_BOOTSTRAP=skip
fi
export PORT_CONFIGURE="./Configure"
export PORT_CONFIGURE_OPTS="OS390-ASCII"
