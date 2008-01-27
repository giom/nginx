#! /bin/sh

PWD=`pwd`
SCRIPT="$PWD/$0"
DIR=`dirname "$SCRIPT"`

cd "$DIR"

DIST=`sed -e '1s/ \+/-/;q' < README`
PATCHES="$DIR/$DIST"/nginx-patches

mkdir "$DIST"
mkdir "$PATCHES"

git format-patch -o "$PATCHES" heads/memcached_hash ^stable ../server/

cp Changes config ngx_http_upstream_memcached_hash_module.c README "$DIST" ||
  exit 1

tar -cvjf "$DIST".tar.bz2 "$DIST"

rm -rf "$DIST"
