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

rm -rf scratch
mkdir -p scratch/token
export SOFTHSM2_CONF=./token.conf
softhsm2-util --slot=0 --init-token --label=functest --pin=123456 --so-pin=12345678
relic="relic -c ./testconf.yml"
verify_2048p="relic verify --cert testkeys/rsa2048.pgp"
verify_2048x="relic verify --cert testkeys/rsa2048.crt"
$relic import-key -k rsa2048 -f testkeys/rsa2048.key
$relic serve &
spid=$!
trap "kill $spid" EXIT INT QUIT TERM

signed=scratch/signed
mkdir -p $signed
echo

### RPM
pkg="zlib-1.2.8-10.fc24.i686.rpm"
relic verify --cert "testkeys/RPM-GPG-KEY-fedora-25-i386" "packages/$pkg"
$relic remote sign -k rsa2048 -f "packages/$pkg" -o "$signed/$pkg"
relic verify "$signed/$pkg" 2>/dev/null && { echo expected an error; exit 1; }
$verify_2048p "$signed/$pkg"
echo

### Starman
pkg="zlib-1.2.8-10.fc24.i686.tar"
$relic remote sign -k rsa2048 -f "packages/$pkg" -o "$signed/$pkg"
$verify_2048p "$signed/$pkg"
echo

### DEB
pkg="zlib1g_1.2.8.dfsg-5_i386.deb"
$relic remote sign -k rsa2048 -f "packages/$pkg" -o "$signed/$pkg"
relic verify "$signed/$pkg" 2>/dev/null && { echo expected an error; exit 1; }
$verify_2048p "$signed/$pkg"
echo

### PGP
relic verify "packages/InRelease" 2>/dev/null && { echo expected an error; exit 1; }
relic verify --cert "testkeys/ubuntu2012.pgp" "packages/InRelease"
relic verify "packages/Release.gpg" --content "packages/Release" 2>/dev/null && { echo expected an error; exit 1; }
relic verify --cert "testkeys/ubuntu2012.pgp" "packages/Release.gpg" --content "packages/Release"
$relic remote sign-pgp -u rsa2048 -ba "packages/Release" -o "$signed/Release.gpg"
$verify_2048p "$signed/Release.gpg" --content "packages/Release"
$relic remote sign-pgp -u rsa2048 --clearsign "packages/Release" -o "$signed/InRelease"
$verify_2048p "$signed/InRelease"
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
relic verify --cert "testkeys/ralph.crt" "packages/$pkg"
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
relic verify --cert "testkeys/msroot.crt" "packages/$pkg"
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
relic verify --cert "testkeys/ralph.crt" "packages/$pkg"
$relic remote sign -k rsa2048 -f "packages/$pkg" -o "$signed/$pkg"
$verify_2048x "$signed/$pkg"
echo

### APK
pkg="dummy.apk"
$relic remote sign -k rsa2048 -f "packages/$pkg" -o "$signed/$pkg" -T jar --apk-v2-present
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
