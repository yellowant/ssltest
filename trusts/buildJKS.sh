for i in *; do
    [ ! -d "$i" ] && continue
    echo $i
    for c in $i/*; do
	keytool -importcert -keystore "$i.jks" -storepass changeit -alias "$c" -file "$c" -noprompt
    done
done
