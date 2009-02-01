#! /bin/sh

BRANCH=$1
if [ "x$BRANCH" = "x" ]; then
    echo "Usage: $0 NGINX-BRANCH"
    exit 1
fi

PWD=`pwd`
SCRIPT="$PWD/$0"
DIR=`dirname "$SCRIPT"`

cd "$DIR"

DIST=`sed -e '1s/ \+/-/;q' < README`
PATCHES="$DIR/$DIST"/nginx-patches

mkdir "$DIST"
mkdir "$PATCHES"

git format-patch -o "$PATCHES" HEAD ^$BRANCH ^devel ^stable ../server/

cp Changes config ngx_http_upstream_memcached_hash_module.c README "$DIST" ||
  exit 1

tar -cvjf "$DIST".tar.bz2 "$DIST"

rm -rf "$DIST"
