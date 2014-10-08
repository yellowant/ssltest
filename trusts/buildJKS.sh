#!/bin/bash

for i in *; do
    [ ! -d "$i" ] && continue
    [[ "$i" == _* ]] && continue
    echo $i
    rm -f "$i.jks"
    for c in $i/*; do
	keytool -importcert -keystore "$i.jks" -storepass changeit -alias "$c" -file "$c" -noprompt
    done
done
