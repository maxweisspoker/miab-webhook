# Mail-in-a-Box Webhook for Cert-Manager

This is an ACME dns-01 challenge webhook for cert-manager, using a Mail-in-a-Box instance to set the ACME challenge TXT records. This allows you to easily provision Let's Encrypt certs for your domain on your Kubernetes cluster with cert-manager.

This webhook was created with simplicity and security in mind, to solve a need I had. It utilizes the [miabhttp](https://github.com/maxweisspoker/miabhttp) library for Go, which I also wrote, since there are no other Go libraries for interacting with the Mail-in-a-box HTTP API.

By default, the Dockerfile builds a single static binary in a "from scratch" image, embedding everything, includes the root CA's, into it. However, as you will note in the Dockerfile comments, you can easily build an Alpine-based or other image which utilizes system certificates and allows for container navigation.

This webhook is extremely straightforward to install and use, except for one snag: when you install cert-manager in your cluster, you must use the --dns01-recursive-nameservers-only and --dns01-recursive-nameservers arguments, and one of the two possible dns01-recursive-nameservers must be your Mail-in-a-box IP. For reasons that elude me, cert-manager fails to see that the TXT record is set unless you add in your MIAB instance.

Although I have confidence in this project, I must still note that it is fairly new, and I am not the best coder, so there are no guarantees and you use it at your own risk.

Here is an example setup completely from scratch, using a KinD cluster, to demonstrate how easy it is to get going with this webhook.

```
$ kind create cluster

Creating cluster "kind" ...
 ✓ Ensuring node image (kindest/node:v1.24.0) 🖼
 ✓ Preparing nodes 📦  
 ✓ Writing configuration 📜 
 ✓ Starting control-plane 🕹️ 
 ✓ Installing CNI 🔌
 ✓ Installing StorageClass 💾 
Set kubectl context to "kind-kind"
You can now use your cluster with:

kubectl cluster-info --context kind-kind

Have a question, bug, or feature request? Let us know! https://kind.sigs.k8s.io/#community 🙂

$ helm install \
  cert-manager jetstack/cert-manager \
  --namespace cert-manager \
  --create-namespace \
  --version v1.8.0 \
  --set 'installCRDs=true,extraArgs={--dns01-recursive-nameservers-only,--dns01-recursive-nameservers=1.1.1.1:53\,YOUR_MIAB_IP:53}'

NAME: cert-manager
LAST DEPLOYED: Sat Jun  4 00:52:41 2022
NAMESPACE: cert-manager
STATUS: deployed
REVISION: 1
TEST SUITE: None
NOTES:
cert-manager v1.8.0 has been deployed successfully!

In order to begin issuing certificates, you will need to set up a ClusterIssuer
or Issuer resource (for example, by creating a 'letsencrypt-staging' issuer).

More information on the different types of issuers and how to configure them
can be found in our documentation:

https://cert-manager.io/docs/configuration/

For information on how to configure cert-manager to automatically provision
Certificates for Ingress resources, take a look at the `ingress-shim`
documentation:

https://cert-manager.io/docs/usage/ingress/

$ kubectl create namespace miab-webhook
namespace/miab-webhook created

$ kubectl create -n miab-webhook secret generic miab-creds --from-literal=server=box.example.com --from-literal=username=admin@example.com --from-literal=password=my_miab_pass
secret/miab-creds created

$ git clone https://github.com/maxweisspoker/miab-webhook
Cloning into 'miab-webhook'...
remote: Enumerating objects: 43, done.
remote: Counting objects: 100% (43/43), done.
remote: Compressing objects: 100% (29/29), done.
remote: Total 43 (delta 15), reused 40 (delta 12), pack-reused 0
Receiving objects: 100% (43/43), 61.67 KiB | 4.40 MiB/s, done.
Resolving deltas: 100% (15/15), done.

$ cd miab-webhook/deploy

$ helm install miab-webhook --namespace miab-webhook --set 'groupName=box.example.com' .
NAME: miab-webhook
LAST DEPLOYED: Sat Jun  4 01:06:34 2022
NAMESPACE: miab-webhook
STATUS: deployed
REVISION: 1
TEST SUITE: None

$ cat <<EOF > cluster-issuer.yaml
apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata:
  name: miab-issuer
spec:
  acme:
    email: admin@example.com
    server: https://acme-staging-v02.api.letsencrypt.org/directory
    privateKeySecretRef:
      name: acme-miab-secret
    solvers:
    - dns01:
        webhook:
          groupName: box.example.com
          solverName: mail-in-a-box
          config:
            MiabContextSecretName: miab-creds
EOF

$ kubectl apply -f cluster-issuer.yaml
clusterissuer.cert-manager.io/miab-issuer created
```

Now you have a ClusterIssuer which can be used to provision a certificate for your subdomain, or any domain for which your Mail-in-a-box instance can set DNS entries. The groupName is set as the domain as an example, but that does not mean you are limited to using that. Under the hood, the "solver" just sends a request to your MIAB server to set a record for the domain listed in the certificate, so if it has the ability to set such a record, the Issuer will work correctly.

This is still a work in progress, and more functionality, as well as helm tests and other useful things, may be added in the future. Feel free to submit PR's!
