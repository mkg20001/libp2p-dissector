#!/bin/bash

# Update .proto files

cd protos

for f in *.proto; do
  if cat $f | grep "^// SRC" > /dev/null 2> /dev/null; then # if has SRC header
    url=$(cat $f | head -n 1 | sed "s|// SRC ||g")
    #curl $url | sed -r 's|(.\|\n)+`((.\|\n)+)`(.\|\n)*|\1|g'
    nc=$(curl "$url" | tr "\n" "_" | sed -r 's|.*`(.*)`.*|\1|g' | tr "_" "\n")
    echo -e "// SRC $url\n\n$nc" > $f
  fi
done

git diff .
