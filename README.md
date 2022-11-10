# polaris-security
polaris-security is polaris submodule to provide authority and authentication ability to applications


## CA Server
### Introduction
polaris-security can act as an intermediate certificate authority, which provides SDS ability in combination with polaris-sidecar-mtls.   

The core of polaris-security CA Server is an https RESTful API: `/security/v1/sign_certificate`, polaris-sidecar-mtls uses this API to periodically renew workload's certificate.  

### Use built-in signer 
polaris-security can sign the certificate by a built-in signer.  
To use this functionality, you should first create secret for it, **or the bootstrap will fail**.   
`deploy/load-certs-into-k8s.sh` is a helper script to create secret. 
To use your own secret materials, you should specify them by environment variable.
```
export CA_CERT_PATH="your_path_to_ca_cert_file"
export CA_KEY_PATH="your_path_to_ca_private_key_file"
export ROOT_CERT_PATH="your_path_to_root_cert_file"
export CERT_CHAIN_PATH="your_path_to_cert_chain_file"
```
If any of these env variable is absent, the script will automatically generate all the certs & key materials.  
Then, just run `load-certs-into-k8s.sh`.  

If the secrets were created successfully, they should appear in namespace `polaris-system`.

```
$ kubectl get secrets -n polaris-system
NAME                                     TYPE                 DATA   AGE
polaris-security-secret                  Opaque               4      1m
```
### Use external signer
polaris-security can use Kubernetes CertificateSignRequest to refer to an external signer (like cert-manager) in the cluster, as an agent.
#### Use cert-manager
About cert-manager signer, refer to [the intro](https://cert-manager.io/docs/configuration/).  

After deployment, to use it as an external signer for polaris-security, you should change `sign` and `sign_namespace` in `deploy/helm/values.yaml`
the naming convention is explained in [the doc](https://cert-manager.io/docs/usage/kube-csr/).  

as an example：
|  type   | signer | sign_namespace |
|  ----  | ----  | ---- |
|cert-manager clusterissuer|clusterissuers.cert-manager.io/ca-issuer|""|
|cert-manager namespaced issuer|issuers.cert-manager.io/polaris-system.ca-issuer|polaris-system|

#### Use tcs-issuer
Trusted Certificate Service (TCS) is a Kubernetes certificate signing solution that uses the security capabilities provided by Intel® Software Guard Extensions (Intel® SGX). The signing key is stored and used inside the Intel SGX enclave(s) and is never stored in clear anywhere in the system.

Follow the deployment steps in [the doc](https://github.com/intel/trusted-certificate-issuer), the naming convection is similar.

### Deploy sidecar secret
whether you use built-in signer or external signer, you should create a secret which contains root-cert for polaris-sidecar to make a TLS-secured SDS request.
```
$ kubectl create secret generic polaris-sidecar-secret -n ${NAMESPACE} \
    --from-file=root-cert=${ROOT_CERT_PATH}
```
```
$ kubectl get secrets -n polaris-system
NAME                                     TYPE                 DATA   AGE
...
polaris-sidecar-secret                   Opaque               1      1m
```
### Deploy polaris-security
**After built-in signer or external signer preparation**, you can use Helm to deploy polaris-security ca server, replacing `${release_name}` with your desired release name, change arguments in `values.yaml` as you like.
```
cd deploy/helm
helm install ${release_name} .
```

to delete polaris-security ca server, you just need to run   
```
helm uninstall `${release_name}`
```

### Arguments explanation
|  argument   | explanation  |
|  ----  | ----  |
|bind | ip address to bind |
|port| port to listen| 
|default_cert_ttl| default signing certificate TTL (in seconds), which is used when the TTL in signing request is wrong|
|dns_names|dns names used as SAN in ca self-signed service certificate,use ',' to delimit multiple names, example: polaris-security,polaris-svc|
|signer| external signer service name|
