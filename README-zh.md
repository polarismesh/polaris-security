[English](./README.md) | 简体中文
# polaris-security
polaris-security是polarismesh的一个子组件，用来向网格内的微服务实例提供证书服务。


## 证书签发服务
### 介绍
polaris-security可以作为中间证书签发机构使用，与polaris-sidecar协作提供[SDS（Secret Discovery Service）](https://www.envoyproxy.io/docs/envoy/latest/configuration/security/secret)能力。   
polaris-security的证书签发功能核心是一个RESTful风格的HTTPS API： `/security/v1/sign_certificate`， polaris-sidecar会周期性地请求此API进行证书签名以轮转微服务实例的证书。
### 使用内置的signer 
polaris-security内置了一个可以完成证书签名工作的signer。    
要使用此功能，您需要为polaris-security创建一个Kubernetes secret， **否则启动过程会失败**。     
`deploy/load-certs-into-k8s.sh`是一个用来帮助创建secret的工具脚本，可以使用环境变量来指定用户自定义的签发材料，设置完毕后，运行此脚本即可创建Kubernetes secret：
```
export CA_CERT_PATH="your_path_to_ca_cert_file"
export CA_KEY_PATH="your_path_to_ca_private_key_file"
export ROOT_CERT_PATH="your_path_to_root_cert_file"
export CERT_CHAIN_PATH="your_path_to_cert_chain_file"
```
如果任一环境变量缺失，脚本会自动生成所有需要的材料。

运行脚本后，`polaris-system`下出现名为`polaris-security-secret`的secret则创建成功。   

```
$ kubectl get secrets -n polaris-system
NAME                                     TYPE                 DATA   AGE
polaris-security-secret                  Opaque               4      1m
```
### 使用外部signer
polaris-security也支持使用Kubernetes [CertificateSignRequest](https://kubernetes.io/docs/reference/access-authn-authz/certificate-signing-requests/)来访问集群内的其他signer来完成证书签发，在此模式下，polaris-security仅起中间代理的作用。
#### 使用cert-manager
关于cert-manager signer的信息，可以参阅[文档](https://cert-manager.io/docs/configuration/).  

在signer部署完毕后，需要修改`deploy/helm/values.yaml`中的`sign`与`sign_namespace`字段来指向此signer以让polaris-security知道如何完成转发，命名规则在[文档](https://cert-manager.io/docs/usage/kube-csr/)中有详细解释。

字段填入示例：
|  类型   | signer | sign_namespace |
|  ----  | ----  | ---- |
|cert-manager clusterissuer|clusterissuers.cert-manager.io/ca-issuer|""|
|cert-manager namespaced issuer|issuers.cert-manager.io/polaris-system.ca-issuer|polaris-system|

#### 使用tcs-issuer
Trusted Certificate Service (TCS) 是基于Intel® Software Guard Extensions (Intel® SGX)机密计算技术完成的一套Kubernetes证书签名解决方案。在此方案下，签名用的私钥会被保存在Intel SGX安全容器内部，签发过程也会在内部进行，杜绝了密钥泄露的风险，具有较高的安全性。

tcs-issuer的部署方法请参阅[文档](https://github.com/intel/trusted-certificate-issuer),命名规则也是类似的。
### 部署polaris-sidecar使用的secret
不论您使用内置或外部的signer，都需要为polaris-sidecar创建一个包含根证书的secret，以用于在发送CSR请求时对polaris-security的身份进行TLS认证。
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
### 部署polaris-security
**在完成上述准备工作后**, 您可以使用Helm来部署polaris-security, `values.yaml`中的参数可以进行自定义调整。
```
cd deploy/helm
helm install ${release_name} .
```

to delete polaris-security ca server, you just need to run   
```
helm uninstall `${release_name}`
```

### 启动参数解析
|  参数   | 解释  |
|  ----  | ----  |
|bind | 要绑定的ip地址 |
|port| 要监听的端口| 
|default_cert_ttl| 默认的证书过期时间，在CSR中的过期时间错误或不存在时使用|
|dns_names|polaris-security自签名的服务证书中的SAN使用的dns名称，以逗号分隔，示例: polaris-security,polaris-svc|
|signer|外部signer名字，若使用内部signer，则该值填空字符串""即可|
