for v in 20130119 20140325 20140927; do
echo $v

wget "http://ftp.de.debian.org/debian/pool/main/c/ca-certificates/ca-certificates_${v}_all.deb" -N

mkdir -p _ca-certificates-deb_$v
cd _ca-certificates-deb_$v
ar x ../ca-certificates_${v}_all.deb
tar xf data.tar.*
cd ..

rm -Rf debian_$v
mkdir -p debian_$v
for d in _ca-certificates-deb_$v/usr/share/ca-certificates/*; do
    for c1 in $d/*; do
	cp $c1 debian_$v/$(basename $d)_$(basename $c1)
    done
done
pushd debian_$v
bash ../hash.sh
popd

done
