for i in $(find . -name "*.pem" -or -name "*.crt"); do
    csplit -z "$i" -f "$i." -b "%d.crt" "/^-----BEGIN CERTIFICATE--/" "{*}" >/dev/null
    rm $i
done
for i in *.crt; do
    name=$(openssl x509 -in "$i" -noout -fingerprint -sha512 | sed "s/.*=//" | tr -d ":")
    echo $name
    openssl x509 -in "$i" -out "$name.crt"
    rm $i
done
