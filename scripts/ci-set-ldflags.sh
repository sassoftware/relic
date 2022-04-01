# If this is a release build, set version to the tag. Otherwise set it to the commit hash.
version="${GITHUB_REF#refs/tags/v*}"
[ "$version" == "$GITHUB_REF" ] && version=$GITHUB_SHA

ldflags="-s -w -X main.version=$version -X main.commit=$GITHUB_SHA"

# Propagate these flags to all further steps in the current job
echo "ldflags=$ldflags" >> $GITHUB_ENV
