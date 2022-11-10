#!/usr/bin/env bash
function GenerateDefaultMaterials() {
    # generate all materials in case that user does not provide them
    TMP_DIR="tmp"
    mkdir -p ${TMP_DIR}
    cp -r ${TOOL_DIR}/* ${TMP_DIR}
    pushd ${TMP_DIR}
    ./generate-test-certs.sh
    mv ca-cert.pem ${CERTS_DIR}/
    mv ca-key.pem ${CERTS_DIR}/
    mv cert-chain.pem ${CERTS_DIR}/
    mv root-cert.pem ${CERTS_DIR}/
    popd
    rm -rf ${TMP_DIR}
}

NAMESPACE=polaris-system
SCRIPT_DIR="$( cd -- "$( dirname -- "${BASH_SOURCE[0]:-$0}"; )" &> /dev/null && pwd 2> /dev/null; )";
TOOL_DIR=${SCRIPT_DIR}/../tools
CERTS_DIR=${SCRIPT_DIR}/../certs

mkdir -p ${CERTS_DIR}

if [[ -z ${CA_CERT_PATH} ]] || [[ -z ${CA_KEY_PATH} ]] || [[ -z ${ROOT_CERT_PATH} ]] || [[ -z ${CERT_CHAIN_PATH} ]]; then
    GenerateDefaultMaterials
    # use the default materials
    CA_CERT_PATH=${CERTS_DIR}/ca-cert.pem
    CA_KEY_PATH=${CERTS_DIR}/ca-key.pem
    ROOT_CERT_PATH=${CERTS_DIR}/root-cert.pem
    CERT_CHAIN_PATH=${CERTS_DIR}/cert-chain.pem
fi

kubectl create ns ${NAMESPACE}

# create secret for polaris-security
kubectl create secret generic polaris-security-secret -n ${NAMESPACE} \
    --from-file=ca-cert=${CA_CERT_PATH} \
    --from-file=ca-key=${CA_KEY_PATH} \
    --from-file=root-cert=${ROOT_CERT_PATH} \
    --from-file=cert-chain=${CERT_CHAIN_PATH}

# create secret for polaris-sidecar
kubectl create secret generic polaris-sidecar-secret -n ${NAMESPACE} \
    --from-file=root-cert=${ROOT_CERT_PATH}
