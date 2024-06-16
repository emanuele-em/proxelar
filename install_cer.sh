cd ./proxyapi/src/ca/

rm ./*.cer ./*.key

openssl genrsa \
    -out proxelar.key 4096

openssl req \
    -x509 \
    -new \
    -nodes \
    -key proxelar.key \
    -sha512 \
    -days 3650 \
    -out proxelar.cer \
    -subj "/CN=proxelar"
