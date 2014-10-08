for i in *; do
    name=`openssl x509 -in "$i" -noout -fingerprint -sha512 | sed "s/.*=//" | tr -d ":"`
    echo $name
    mv "$i" "$name.pem"
done
