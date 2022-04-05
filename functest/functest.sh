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


cd $(dirname $0)
set -ex
srcdir=$(pwd -P)

rm -rf scratch
mkdir -p scratch/token
export SOFTHSM2_CONF=./token.conf
softhsm2-util --slot=0 --init-token --label=functest --pin=123456 --so-pin=12345678
GOOS=$(go env GOOS)
GOARCH=$(go env GOARCH)
if [ -e ../build/relic-$GOOS-$GOARCH ]
then
    client=../build/relic-$GOOS-$GOARCH
else
    client=relic
fi
relic="$client -c ./testconf.yml"
verify_2048p="$client verify --cert testkeys/rsa2048.pgp"
verify_2048x="$client verify --cert testkeys/rsa2048.crt"
$relic import-key -k rsa2048 -f testkeys/rsa2048.key
$relic serve &
spid=$!
trap "kill $spid" EXIT INT QUIT TERM

signed=scratch/signed
mkdir -p $signed
echo

set +x
for x in {1..100}
do
    curl -skf https://localhost:6363/health && break
    if [ i == 100 ]
    then
        echo server failed to start
        exit 1
    fi
    sleep 0.1
done
set -x

### RPM
pkg="zlib-1.2.8-10.fc24.i686.rpm"
$client verify --cert "testkeys/RPM-GPG-KEY-fedora-25-i386" "packages/$pkg"
$relic remote sign -k rsa2048 -f "packages/$pkg" -o "$signed/$pkg"
$client verify "$signed/$pkg" 2>/dev/null && { echo expected an error; exit 1; }
$verify_2048p "$signed/$pkg"
echo

### DEB
pkg="zlib1g_1.2.8.dfsg-5_i386.deb"
$relic remote sign -k rsa2048 -f "packages/$pkg" -o "$signed/$pkg"
$client verify "$signed/$pkg" 2>/dev/null && { echo expected an error; exit 1; }
$verify_2048p "$signed/$pkg"
echo

### PGP
$client verify "packages/InRelease" 2>/dev/null && { echo expected an error; exit 1; }
$client verify --cert "testkeys/ubuntu2012.pgp" "packages/InRelease"
$client verify "packages/Release.gpg" --content "packages/Release" 2>/dev/null && { echo expected an error; exit 1; }
$client verify --cert "testkeys/ubuntu2012.pgp" "packages/Release.gpg" --content "packages/Release"
$relic remote sign-pgp -u rsa2048 -ba "packages/Release" -o "$signed/Release.gpg"
$verify_2048p "$signed/Release.gpg" --content "packages/Release"
$relic remote sign-pgp -u rsa2048 --clearsign "packages/Release" -o "$signed/InRelease"
$verify_2048p "$signed/InRelease"
$relic remote sign-pgp -u rsa2048 "packages/Release" -o "$signed/Release.inline"
$verify_2048p "$signed/Release.inline"
echo

### JAR
pkg="hello.jar"
$relic remote sign -k rsa2048 -f "packages/$pkg" -o "$signed/$pkg"
$verify_2048x "$signed/$pkg"
echo

### EXE
pkg="ClassLibrary1.dll"
$relic remote sign -k rsa2048 -f "packages/$pkg" -o "$signed/$pkg"
$verify_2048x "$signed/$pkg"
echo

### MSI
pkg="dummy.msi"
$relic remote sign -k rsa2048 -f "packages/$pkg" -o "$signed/$pkg"
$verify_2048x "$signed/$pkg"
echo

### appx
pkg="App1_1.0.3.0_x64.appx"
$client verify --cert "testkeys/ralph.crt" "packages/$pkg"
$relic remote sign -k rsa2048 -f "packages/$pkg" -o "$signed/$pkg"
$verify_2048x "$signed/$pkg"
echo

### CAB
pkg="dummy.cab"
$relic remote sign -k rsa2048 -f "packages/$pkg" -o "$signed/$pkg"
$verify_2048x "$signed/$pkg"
echo

### CAT
pkg="hyperv.cat"
$relic remote sign -k rsa2048 -f "packages/$pkg" -o "$signed/$pkg"
$verify_2048x "$signed/$pkg"
echo

### XAP
pkg="dummy.xap"
$relic remote sign -k rsa2048 -f "packages/$pkg" -o "$signed/$pkg"
$verify_2048x "$signed/$pkg"
echo

### Powershell
pkg="hello.ps1"
$relic remote sign -k rsa2048 -f "packages/$pkg" -o "$signed/$pkg"
$verify_2048x "$signed/$pkg"
pkg="hello.ps1xml"
$relic remote sign -k rsa2048 -f "packages/$pkg" -o "$signed/$pkg"
$verify_2048x "$signed/$pkg"
pkg="hello.mof"
$relic remote sign -k rsa2048 -f "packages/$pkg" -o "$signed/$pkg"
$verify_2048x "$signed/$pkg"
echo

### ClickOnce
pkg="WindowsFormsApplication1.exe.manifest"
$relic remote sign -k rsa2048 -f "packages/$pkg" -o "$signed/$pkg"
$verify_2048x "$signed/$pkg"
echo

### VSIX
pkg="VSIXProject1.vsix"
$client verify --cert "testkeys/ralph.crt" "packages/$pkg"
$relic remote sign -k rsa2048 -f "packages/$pkg" -o "$signed/$pkg"
$verify_2048x "$signed/$pkg"
echo

### APK
pkg="dummy.apk"
$relic remote sign -k rsa2048 -f "packages/$pkg" -o "$signed/$pkg" -T jar --apk-v2-present
$relic remote sign -k rsa2048 -f "$signed/$pkg"
$verify_2048x "$signed/$pkg"
echo

### Mach-O
pkg="slimfile.app"
$relic remote sign -k rsa2048 -f "packages/$pkg/dummyapp" --info-plist "packages/$pkg/Info.plist" --resources "packages/$pkg/_CodeSignature/CodeResources" -o "$signed/slimfile.macho"
$verify_2048x "$signed/slimfile.macho"
( cd $signed && mkdir -p Payload && cp -r $srcdir/packages/$pkg Payload/ && cp -f slimfile.macho Payload/$pkg/dummyapp && zip -r slimfile.ipa Payload )
$verify_2048x "$signed/slimfile.ipa"
echo

### DMG
pkg="dummy.dmg"
$relic remote sign -k rsa2048 -f "packages/$pkg" -o "$signed/$pkg"
$verify_2048x "$signed/$pkg"
echo

### PKG
pkg="dummy.pkg"
$relic remote sign -k rsa2048 -f "packages/$pkg" -o "$signed/$pkg"
$relic remote sign -k rsa2048 -f "$signed/$pkg"
$verify_2048x "$signed/$pkg"
echo

### X.509 certificate operations
$relic x509-self-sign -k root --generate-rsa 2048 --cert-authority -n "functest CA" >"$signed/root.crt"
$relic x509-request -k inter --generate-ecdsa 384 --commonName "functest inter" >"$signed/inter.csr"
$relic x509-sign -k root --cert-authority "$signed/inter.csr" > "$signed/inter.crt"
$relic x509-request -k leaf --generate-ecdsa 256 --commonName "functest leaf" --alternate-dns leaf.localdomain >"$signed/leaf.csr"
$relic x509-sign -k inter --copy-extensions "$signed/leaf.csr" > "$signed/leaf.crt"
openssl verify -check_ss_sig -CAfile "$signed/root.crt" -untrusted "$signed/inter.crt" "$signed/leaf.crt"

trap - EXIT
kill -QUIT $spid
wait $spid

set +x
echo
echo OK
echo
