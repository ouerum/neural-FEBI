#!/usr/bin/env bash

#------------------------------------------------------------------------------
# This script builds the solidity binary using Emscripten.
# Emscripten is a way to compile C/C++ to JavaScript.
#
# http://kripken.github.io/emscripten-site/
#
# First run install_dep.sh OUTSIDE of docker and then
# run this script inside a docker image trzeci/emscripten
#
# The documentation for solidity is hosted at:
#
# http://solidity.readthedocs.io/
#
# ------------------------------------------------------------------------------
# This file is part of solidity.
#
# solidity is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# solidity is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with solidity.  If not, see <http://www.gnu.org/licenses/>
#
# (c) 2016 solidity contributors.
#------------------------------------------------------------------------------

set -ev

if test -z "$1"; then
	BUILD_DIR="emscripten_build"
else
	BUILD_DIR="$1"
fi

if ! type git &>/dev/null; then
    # We need git for extracting the commit hash
    apt-get update
    apt-get -y install git-core
fi

if ! type wget &>/dev/null; then
    # We need wget to install cmake
    apt-get update
    apt-get -y install wget
fi

WORKSPACE=/root/project

# Increase nodejs stack size
if ! [ -e /emsdk_portable/node/current/bin/node_orig ]
then
  mv /emsdk_portable/node/current/bin/node /emsdk_portable/node/current/bin/node_orig
  echo -e '#!/bin/sh\nexec /emsdk_portable/node/current/bin/node_orig --stack-size=8192 $@' > /emsdk_portable/node/current/bin/node
  chmod 755 /emsdk_portable/node/current/bin/node
fi

# Boost
echo -en 'travis_fold:start:compiling_boost\\r'
test -e "$WORKSPACE"/boost_1_70_0_install/include/boost/version.hpp || (
cd "$WORKSPACE"/boost_1_70_0
./b2 toolset=emscripten link=static variant=release threading=single runtime-link=static \
       --with-system --with-filesystem --with-test --with-program_options cxxflags="-Wno-unused-local-typedef -Wno-variadic-macros -Wno-c99-extensions -Wno-all" \
       --prefix="$WORKSPACE"/boost_1_70_0_install install
)
ln -sf "$WORKSPACE"/boost_1_70_0_install/lib/* /emsdk_portable/emscripten/sdk/system/lib
ln -sf "$WORKSPACE"/boost_1_70_0_install/include/* /emsdk_portable/emscripten/sdk/system/include
echo -en 'travis_fold:end:compiling_boost\\r'

echo -en 'travis_fold:start:install_cmake.sh\\r'
source $WORKSPACE/scripts/install_cmake.sh
echo -en 'travis_fold:end:install_cmake.sh\\r'

# Build dependent components and solidity itself
echo -en 'travis_fold:start:compiling_solidity\\r'
cd $WORKSPACE
mkdir -p $BUILD_DIR
cd $BUILD_DIR
cmake \
  -DCMAKE_TOOLCHAIN_FILE=../cmake/toolchains/emscripten.cmake \
  -DCMAKE_BUILD_TYPE=Release \
  -DBoost_USE_STATIC_LIBS=1 \
  -DBoost_USE_STATIC_RUNTIME=1 \
  -DTESTS=0 \
  ..
make -j 4

cd ..
mkdir -p upload
# Patch soljson.js to provide backwards-compatibility with older emscripten versions
# TODO: remove in 0.6.0!
echo -n ";/* backwards compatibility */ Module['Runtime'] = Module; Module['Pointer_stringify'] = Module['UTF8ToString'];" >> $BUILD_DIR/libsolc/soljson.js
cp $BUILD_DIR/libsolc/soljson.js upload/
cp $BUILD_DIR/libsolc/soljson.js ./

OUTPUT_SIZE=`ls -la soljson.js`

echo "Emscripten output size: $OUTPUT_SIZE"

echo -en 'travis_fold:end:compiling_solidity\\r'
