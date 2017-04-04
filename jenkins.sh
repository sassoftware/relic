#!/bin/bash
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
mkdir -p $GOPATH/src/$(dirname $module)
ln -sfn $WORKDIR/checkout $GOPATH/src/$module

mkdir -p $WORKDIR/build
cd $GOPATH/src/$module
glide i
# Block access to unvendored libs from this point on
export GIT_ALLOW_PROTOCOL=none
# Make sure version gets updated
touch $GOPATH/src/$module/config/config.go
GOOS=linux go build -v -ldflags "$ldflags" -o $WORKDIR/build/relic $module/relic
GOOS=linux go build -v -ldflags "$ldflags" -o $WORKDIR/build/relic-audit $module/relic/relic-audit
GOOS=windows go build -v -ldflags "$ldflags" -o $WORKDIR/build/relic.exe $module/relic

cd $WORKDIR/build
rhname=relic-redhat-$version
mkdir relic-redhat-$version
cp -a $WORKDIR/checkout/distro/linux/* relic relic-audit $rhname/
sed -i -e "s/^Version:.*/Version: $version/" $rhname/relic.spec
tar -czf ${rhname}.tar.gz $rhname

rm -rf $rhname
