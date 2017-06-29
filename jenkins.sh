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


set -e
export WORKDIR=$(pwd)
export GOPATH=$WORKDIR/go
export GO15VENDOREXPERIMENT=1
export PATH=$GOPATH/bin:$GOROOT/bin:$PATH
rm -rf $WORKDIR/build

[ -x $GOPATH/bin/glide ] || go get -v github.com/Masterminds/glide

module=$(grep ^package: checkout/glide.yaml |cut -d' ' -f2)
version=$(cd checkout && git describe --tags |sed -e 's/-\([0-9]*\).*/.\1/')
[ -n "$version" ] || { echo Unable to determine version; exit 1; }
ldflags="-X ${module}/config.Version=$version"
echo "Version: $version"
echo "Go version: $(go version)"
mkdir -p $GOPATH/src/$(dirname $module)
ln -sfn $WORKDIR/checkout $GOPATH/src/$module

mkdir -p $WORKDIR/build
cd $GOPATH/src/$module
glide i
# Block access to unvendored libs from this point on
export GIT_ALLOW_PROTOCOL=none
# Make sure version gets updated
touch $GOPATH/src/$module/config/config.go
GOOS=linux go build -v -ldflags "$ldflags" -o $WORKDIR/build/relic $module
GOOS=windows go build -v -ldflags "$ldflags" -o $WORKDIR/build/relic.exe $module

cd $WORKDIR/build
rhname=relic-redhat-$version
mkdir relic-redhat-$version
cp -a $WORKDIR/checkout/distro/linux/* relic $rhname/
sed -i -e "s/^Version:.*/Version: $version/" $rhname/relic.spec
tar -czf ${rhname}.tar.gz $rhname

rm -rf $rhname
