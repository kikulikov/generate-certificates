#!/usr/bin/env bash
set -o pipefail
set -eu

echo "> Generates self-signed certificates for testing"

readonly dir="./certificates"
mkdir -p ${dir}

readonly ca_key_path="${dir}/rootCA.key"
readonly ca_cert_path="${dir}/rootCA.pem"

# If you are generating a self signed cert, you can do both the key and cert in one command like so:
# openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 10000 -nodes

if [ ! -f ${ca_key_path} ]; then
    echo ""
    echo "> Create a root key"
    openssl genrsa -out ${ca_key_path} 2048
fi

if [ ! -f ${ca_cert_path} ]; then
    echo ""
    echo "> Create a root certificate"
    openssl req -new -x509 -days 3650 -nodes -key ${dir}/rootCA.key \
    -out ${dir}/rootCA.pem -config openssl-root.conf
fi

# Useful openssl commands to view certificate content
# https://www.golinuxcloud.com/openssl-view-certificate/

# View the content of CA certificate
# openssl x509 -noout -text -in certificates/rootCA.pem

# View the content of CSR
# openssl req -noout -text -in certificates/kafka.csr

# View the content of signed Certificate
# openssl x509 -noout -text -in certificates/kafka.crt


function generate {
    component=$1

    if [ ! -f ${dir}/${component}.key ]; then
        echo ""
        echo "> Create a [${component}] private key"
        openssl genrsa -out ${dir}/${component}.key 2048
    fi

    if [ ! -f ${dir}/${component}.csr ]; then
        echo ""
        echo "> Generate a [${component}] CSR certificate"
        openssl req -new -key ${dir}/${component}.key -out ${dir}/${component}.csr \
        -config openssl-${component}.conf
    fi

    if [ ! -f ${dir}/${component}.crt ]; then
        echo ""
        echo "> Sign the [${component}] CSR certificate"
        openssl x509 -req -in ${dir}/${component}.csr -CA ${dir}/rootCA.pem \
        -CAkey ${dir}/rootCA.key -CAcreateserial -out ${dir}/${component}.crt \
        -days 3650 -extfile openssl-${component}.conf -extensions v3_req
    fi

    truststore_path="${dir}/${component}.truststore.jks"
    truststore_storepass="confluent"
    cert_path="${dir}/${component}.crt"
    key_path="${dir}/${component}.key"
    ssl_key_password="confluent"
    keystore_path="${dir}/${component}.keystore.jks"
    keystore_storepass="confluent"

    rm -f ${truststore_path} ${keystore_path}

    # Create Truststore and Import the CA Cert
    keytool -noprompt -keystore ${truststore_path} \
      -storetype pkcs12 \
      -alias CARoot \
      -import -file ${ca_cert_path} \
      -storepass ${truststore_storepass} \
      -keypass ${truststore_storepass}

    # Put Key and Signed Cert into pkcs12 Format with Key Password
    openssl pkcs12 -export \
      -in ${cert_path} \
      -inkey ${key_path} \
      -passin pass:${ssl_key_password} \
      -out ${dir}/${component}.p12 \
      -name kafkassl \
      -passout pass:mykeypassword

    # Create Keystore
    keytool -importkeystore \
      -srckeystore ${dir}/${component}.p12 \
      -srcstoretype pkcs12 \
      -srcstorepass mykeypassword \
      -destkeystore ${keystore_path} \
      -deststoretype pkcs12 \
      -deststorepass ${keystore_storepass} \
      -destkeypass ${keystore_storepass}

    # Import the CA Cert into Keystore
    keytool -noprompt -keystore ${keystore_path} \
      -storetype pkcs12 \
      -alias CARoot \
      -import -file ${ca_cert_path} \
      -storepass ${keystore_storepass} \
      -keypass ${keystore_storepass}

    # keytool -keystore kafka.server.keystore.jks -alias localhost -keyalg RSA -validity 3650 -genkey
    # # openssl req -new -x509 -keyout ca-key -out ca-cert -days {validity}
    # keytool -keystore kafka.client.truststore.jks -alias CARoot -importcert -file rootCA.pem
    # keytool -keystore kafka.server.truststore.jks -alias CARoot -importcert -file rootCA.pem

    # keytool -keystore kafka.server.keystore.jks -alias localhost -certreq -file rootCA.pem
    # # openssl x509 -req -CA ca-cert -CAkey ca-key -in cert-file -out cert-signed -days {validity} -CAcreateserial -passin pass:{ca-password}
    # keytool -keystore kafka.server.keystore.jks -alias CARoot -importcert -file ca-cert
    # keytool -keystore kafka.server.keystore.jks -alias localhost -importcert -file cert-signed

    echo ""
    echo ">>> rootCA.pem contains cacerts"
    echo ">>> ${component}.crt contains fullchain (the full chain)"
    echo ">>> ${component}.key contains privkey (the private key)"
}

for element in kafka client
do
  echo ""
  echo "Generate certificates and keys for ${element}"
  generate $element
done

# keytool -keystore kafka.client.truststore.jks -alias CARoot -import -file rootCA.pem

# # 1. Generate truststore [rootCA.pem as input]
# keytool -keystore kafka.connect.truststore.jks -alias CARoot -import \
# -file rootCA.pem -trustcacerts -deststorepass PASSWD -deststoretype pkcs12 -noprompt

# # 2. Export PKCS12 [connect.crt & connect.key as input]
# openssl pkcs12 -export -in connect.crt -inkey connect.key \
# -out connect.p12 -name connect -passout pass:PASSWD

# # 3. Generate keystore [connect.p12 as input]
# keytool -importkeystore -deststorepass PASSWD -destkeypass PASSWD \
# -destkeystore kafka.connect.keystore.jks -deststoretype pkcs12 \
# -srckeystore connect.p12 -srcstoretype PKCS12 -srcstorepass PASSWD
