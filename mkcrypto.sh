#!/bin/bash

config="./openssl.cnf"
index="./index.txt"
serial="./serial"

mkdir ./generals
mkdir ./ca
mkdir ./certs
mkdir ./crl
mkdir ./newcerts
touch $index
echo 01 > $serial

# Get the hostfile from the command line argument
exec < $1

# Generate private key for CA
openssl genrsa -out ./ca/ca_key.pem 2048

# Generate certificate (public key) for CA
openssl req -batch -new -x509 -extensions v3_ca -key ./ca/ca_key.pem -out ./ca/ca_cert.pem -days 365

i=0

while read line
do
        rm -f ./index.*
        rm -f ./serial*
        touch $index
        echo 01 > $serial

        i=$(($i+1))
        
        # Generate private key for host with id = $i
        openssl genrsa -out ./generals/host_"$i"_key.pem 2048

        # Generate certificate (public key) for host with id = $i
        openssl req -batch -new -extensions v3_ca -key ./generals/host_"$i"_key.pem -out ./generals/host_"$i"_req.pem -days 365

        # Sign the certificate by the CA
        openssl ca -batch -out ./generals/host_"$i"_cert.pem -keyfile ./ca/ca_key.pem -cert ./ca/ca_cert.pem -config $config -infiles ./generals/host_"$i"_req.pem
done
