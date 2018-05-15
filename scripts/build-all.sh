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
set -ex -o pipefail
version=$(./scripts/version.sh)
commit=$(git rev-parse HEAD)
ldflags="-s -w -X github.com/sassoftware/relic/config.Version=$version -X github.com/sassoftware/relic/config.Commit=$commit"

rm -rf build
mkdir build

## non-cgo build of client
docker rmi relic-build 2>/dev/null ||:
docker build \
    -f scripts/Dockerfile.clientbuild \
    --build-arg ldflags="$ldflags" \
    -t relic-build .
container=$(docker create relic-build)
docker cp $container:out build/
docker rm $container
docker rmi relic-build

## cgo build of full program
# build libtool-ltdl as a static library so no deps other than libc are needed
xgo \
    --targets=linux/amd64,darwin/amd64 \
    --deps="http://ftpmirror.gnu.org/libtool/libtool-2.4.6.tar.gz" \
    --depsargs=--disable-shared \
    --out="build/relic" \
    -ldflags "$ldflags" \
    .

mv build/relic-darwin-*-amd64 build/relic-darwin-amd64
mv build/out/* build/
rmdir build/out
