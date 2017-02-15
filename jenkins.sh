#!/bin/bash
set -e
export WORKDIR=$(pwd)
export GOPATH=$WORKDIR/go
export GO15VENDOREXPERIMENT=1
export PATH=$GOPATH/bin:$GOROOT/bin:$PATH
rm -rf $WORKDIR/build

[ -x $GOPATH/bin/glide ] || go get -v github.com/Masterminds/glide

module=$(cd checkout && glide name 2>/dev/null)
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
GOOS=windows go build -v -ldflags "$ldflags" -o $WORKDIR/build/relic.exe $module/relic/relic_notoken

cd $WORKDIR/build
mkdir dist-redhat dist-windows
cp -a $WORKDIR/checkout/distro/linux/* relic dist-redhat/
sed -i -e "s/^Version:.*/Version: $version/" dist-redhat/relic.spec
tar -czf relic-prepkg-redhat.tar.gz dist-redhat
cp -a $WORKDIR/checkout/distro/windows/* relic.exe dist-windows/
sed -i -e "s/ Version=[^ >]*/ Version='$version'/" dist-windows/relic.wxs
zip -rq relic-prepkg-windows.zip dist-windows
rm -rf dist-*
