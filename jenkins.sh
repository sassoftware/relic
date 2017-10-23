#!/bin/bash
#
# Copyright (c) SAS Institute Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

module=github.com/sassoftware/relic

set -e
WORKDIR=$(pwd)
export PATH=$GOROOT/bin:$PATH
rm -rf $WORKDIR/build
mkdir -p $WORKDIR/build

if [ -n "${VENDORIZER:-}" ]
then
    curl -sOz ./vendorizer "$VENDORIZER/vendorizer"
    chmod a+rx vendorizer
    vz="./vendorizer ensure -u $VENDORIZER"
else
    type -P dep >/dev/null || go get -v github.com/golang/dep/cmd/dep
    vz="dep ensure -vendor-only"
fi

# Setup GOPATH
SRCDIR=$(cd $(dirname $0) && pwd)
export GOPATH=$WORKDIR/build/go
version=$(cd "$SRCDIR" && git describe --tags |sed -e 's/-\([0-9]*\).*/.\1/')
[ -n "$version" ] || { echo Unable to determine version; exit 1; }
ldflags="-X ${module}/config.Version=$version"
echo "Version: $version"
echo "Go version: $(go version)"
mkdir -p $GOPATH/src/$(dirname $module)
ln -sfn $SRCDIR $GOPATH/src/$module

echo setting up build directory
cd $GOPATH/src/$module
$vz
# Block access to unvendored libs from this point on
export GIT_ALLOW_PROTOCOL=none

# Make sure version gets updated
echo building
touch $GOPATH/src/$module/config/config.go
GOOS=linux go build -v -ldflags "$ldflags" -o $WORKDIR/build/relic $module
GOOS=windows go build -v -ldflags "$ldflags" -o $WORKDIR/build/relic.exe -tags clientonly $module

cd $WORKDIR/build
rhname=relic-redhat-$version
mkdir relic-redhat-$version
cp -a $SRCDIR/distro/linux/* relic $rhname/
sed -i -e "s/^Version:.*/Version: $version/" $rhname/relic.spec
tar -czf ${rhname}.tar.gz $rhname

rm -rf $rhname
