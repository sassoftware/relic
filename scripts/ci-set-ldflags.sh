# If this is a release build, set version to the tag. Otherwise set it to the commit hash.
version="${GITHUB_REF#refs/tags/v*}"
[ "$version" == "$GITHUB_REF" ] && version=$GITHUB_SHA

ldflags="-s -w -X github.com/sassoftware/relic/config.Version=$version -X github.com/sassoftware/relic/config.Commit=$GITHUB_SHA"

# Propagate these flags to all further steps in the current job
echo "ldflags=$ldflags" >> $GITHUB_ENV
