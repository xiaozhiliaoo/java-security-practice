-- crt文件
openssl version -a
openssl genrsa -out lili.key 2048
openssl rsa -in lili.key -pubout -out lilipublic.key
openssl req -new -key lili.key -out lili.csr
openssl req -text -in lili.csr -noout -verify
openssl x509 -req -days 365 -in lili.csr -signkey lili.key -out lili.crt

CSR(certificate signing request (CSR))

openssl x509 -outform der -in your-cert.pem -out your-cert.crt


-- cer文件
openssl genrsa -out ca.key.pem 2048
openssl req -new -key ca.key.pem -out ca.csr
openssl x509 -req -days 1000 -signkey ca.key.pem -in ca.csr -out ca.cer
openssl pkcs12  -export -cacerts -inkey ca.key.pem -in ca.cer ca.p12