# vault-k8s-jwt-approle-sync

cert-manager lacks the ability to authenticate with Vault via JWT, which can
present problems for Vault users operating at scale in Kubernetes environments.

This app is meant to run in the cert-manager namespace and achieve the
following:

- authenticate with Vault via the JWT Auth Method (using the projected service
account token at `/var/run/secrets/kubernetes.io/serviceaccount/token`)
- request AppRole Secret IDs
- store the Secret ID in a K8s secret object
- rotate the Secret ID at 2/3 of it's TTL

This pattern allows cert-manager to authenticate with AppRole, while
maintaining a sound security posture.

## Considerations

- The request for a Secret ID does not specify a TTL, and consequently relies
on the Auth Method's role for the default value (which should be non-zero).
- The cert-manager configuration must specify the same K8s secret to reference
the AppRole Secret ID.

## Installation

The environment variables in the yaml below are used to configure the
application behavior.

```shell
kubectl create configmap -n cert-manager rotater --from-file=main.go
cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: Pod
metadata:
  name: approle-secretid-rotater
  namespace: cert-manager
  labels:
    app: approle-secretid-rotater
spec:
  serviceAccountName: cert-manager
  containers:
  - name: golang
    image: golang:latest
    env:
      - name: VAULT_ADDR
        value: http://192.168.65.2:8200
      - name: VAULT_AUTH_PATH
        value: jwt
      - name: VAULT_AUTH_ROLE
        value: demo-jwt
      - name: VAULT_NAMESPACE
        value: awesomeNamespace
      - name: VAULT_APP_ROLE_PATH
        value: approle
      - name: VAULT_APP_ROLE_NAME
        value: demo-approle
      - name: SECRET_ID_SECRET
        value: cert-manager-approle
    command: ["/bin/bash", "-c"]
    args: ["mkdir -p /tmp/code && cp /code/rotater.go /tmp/code/main.go && cd /tmp/code && go mod init github.com/rotater && go mod tidy && go run main.go"]
    imagePullPolicy: IfNotPresent
    volumeMounts:
    - name: code-volume
      mountPath: /code
  volumes:
    - name: code-volume
      configMap:
        name: rotater
  restartPolicy: Always
EOF
```
