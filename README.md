# polaris-security
polaris-security is polaris submodule to provide authority and authentication ability to applications


## CA Server
### Introduction
polaris-security can act as an intermediate certificate authority, which provides SDS ability in combination with polaris-sidecar-mtls.   

The core of polaris-security CA Server is an https RESTful API: `/security/v1/sign_certificate`, polaris-sidecar-mtls uses this API to periodically renew workload's certificate.     

### Deployment
#### Create Secret
To use polaris-security, you should first create secret for it, **or the bootstrap will fail**.   
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
polaris-sidecar-secret                   Opaque               1      1m
```

#### Use Helm
**After secret creation**, you can use Helm to deploy polaris-security ca server, replacing `${release_name}` with your desired release name, change arguments in `values.yaml` as you like.
```
cd deploy/helm
helm install ${release_name} .
```

to delete polaris-security ca server, you just need to run   
```
helm uninstall `${release_name}`
```

### arguments explanation
|  argument   | explanation  |
|  ----  | ----  |
|bind | ip address to bind |
|port| port to listen| 
|default_cert_ttl| default signing certificate TTL (in seconds), which is used when the TTL in signing request is wrong|
|dns_names|dns names used as SAN in ca self-signed service certificate,use ',' to delimit multiple names, example: polaris-security,polaris-svc|
