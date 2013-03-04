#!/bin/bash

if [ -d ./generals ]; then
	rm -rf ./generals
fi

if [ -d ./ca ]; then
	rm -rf ./ca
fi

if [ -d ./certs ]; then
	rm -rf ./certs
fi

if [ -d ./crl ]; then
	rm -rf ./crl
fi

if [ -d ./newcerts ]; then
	rm -rf ./newcerts
fi

rm -f ./index.*
rm -f serial*