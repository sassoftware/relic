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

set -ex
version=$(./scripts/version.sh)
[ -e build/relic-linux-amd64 ] || ./scripts/build-all.sh

cd build
rm -f *.rpm
tdir="relic-$version"
rm -rf "$tdir"
mkdir -p "$tdir"
cp -a ../distro/linux/* doc/relic.yml "$tdir/"
cp relic-linux-amd64 "$tdir/relic"
tar -cf relic.tar "$tdir"
sed -i -e "s/^Version:.*/Version: $version/" $tdir/relic.spec
rpmbuild -bb -D "_rpmdir $(pwd)" -D "_sourcedir $(pwd)" $tdir/relic.spec
rm -rf "$tdir"
cd ..
ls -l build/x86_64/*.rpm
