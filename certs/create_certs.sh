#Generate CA Certificate

create_ca() {
  echo "==== Generating CA ===="
  openssl genrsa -out CA.key 2048
  openssl req -new -sha256 -key CA.key -out CA.csr -subj "/CN=*.localhost" -config ../openssl.cnf
  openssl x509 -signkey CA.key -in CA.csr -req -days 3650 -out CA.crt -extensions v3_req -extfile ../openssl.cnf
}

create_intermediary_ca() {
  echo "==== Generating intermediary CA ===="
  openssl genrsa -out Intermediary.key 2048
  openssl req -new -sha256 -key Intermediary.key -out Intermediary.csr -subj "/CN=localhost" -config ../openssl.cnf
  openssl x509 -req -in Intermediary.csr -CA CA.crt -CAkey CA.key -CAcreateserial -out Intermediary.crt -days 3650 -sha256 -extensions v3_req -extfile ../openssl.cnf
}

create_leaf_cert_signed_by_ca() {
  echo "==== Generating server cert signed by CA ===="
  openssl genrsa -out Leaf_signed_by_CA.key 2048
  openssl req -new -sha256 -key Leaf_signed_by_CA.key -out Leaf_signed_by_CA.csr -subj "/CN=localhost" -config ../openssl.cnf
  openssl x509 -req -in Leaf_signed_by_CA.csr -CA CA.crt -CAkey CA.key -CAcreateserial -out Leaf_signed_by_CA.crt -days 3650 -sha256 -extensions v3_req -extfile ../openssl.cnf

  openssl x509 -text -noout -in Leaf_signed_by_CA_signedByCA.crt
}

create_leaf_cert_signed_by_intermediary_ca() {
  echo "==== Generating server cert signed by intermediary CA ===="
  openssl genrsa -out Leaf_signed_by_Intermediary.key 2048
  openssl req -new -sha256 -key Leaf_signed_by_Intermediary.key -out Leaf_signed_by_Intermediary.csr -subj "/CN=localhost" -config ../openssl.cnf
  openssl x509 -req -in Leaf_signed_by_Intermediary.csr -CA CA.crt -CAkey CA.key -CAcreateserial -out Leaf_signed_by_Intermediary.crt -days 3650 -sha256 -extensions v3_req -extfile ../openssl.cnf

  openssl x509 -text -noout -in Leaf_signed_by_Intermediary.crt
}

rm -rf generated
mkdir -p generated
pushd generated

create_ca
create_intermediary_ca
create_leaf_cert_signed_by_ca
create_leaf_cert_signed_by_intermediary_ca

cat CA.crt > Trustbundle_CA.crt
cat {CA,Intermediary}.crt > Trustbundle_Intermediary_Full_Chain.crt
cat Intermediary.crt > Trustbundle_Intermediary_Full_Chain_Rootless.crt
cat {CA,Intermediary,Leaf_signed_by_CA}.crt > Trustbundle_Leaf_signed_by_CA_Full_Chain.crt
cat {Intermediary,Leaf_signed_by_CA}.crt > Trustbundle_Leaf_signed_by_CA_Full_Chain_Rootless.crt
cat {CA,Intermediary,Leaf_signed_by_Intermediary}.crt > Trustbundle_Leaf_signed_by_Intermediary_Full_Chain.crt
cat {CA,Intermediary,Leaf_signed_by_Intermediary}.crt > Trustbundle_Leaf_signed_by_Intermediary_Full_Chain_Rootless.crt

rm -rf *.csr
rm -rf *.srl

popd