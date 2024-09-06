## First enable metrics-server to allow the autoscaler to monitor the host performance

```bash
microk8s enable metrics-server
```

## Apply the ipchecker secrets:

This file contains all the environment variables needed for ipchecker to work. They are base64 encoded

```bash
kubectl apply -f secrets.yml
```

## Apply the ipchecker deployment:

This is the file that set up the image, replicas, cmd to run when deploying a pod, secrets and the container pod that the application will use

```bash
kubectl apply -f deployment.yml
```

## Apply the ipchecker service:

This file that allows the pods to receives a cluster-internal IP address, making its only accessible from within the cluster

```bash
kubectl apply -f ipchecker_service.yml
```

## Apply the ipchecker horizontal pod autoscaling

This file sets up the policies where the pods will be scaled up or down

```bash
kubectl apply -f ipchecker_hpa.yml
```

# Now we start deploying nginx reverse proxy

## First we request selfsigned certficates:

```bash
openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout ./nginx-selfsigned.key -out ./nginx-selfsigned.crt
```
## Second we set up the certificates as k8s secrets:

```bash
# kubectl create secret generic nginx-certs-ipchecker --from-file=nginx-selfsigned.crt --from-file=nginx-selfsigned.key
kubectl create secret generic nginx-certs --from-file=nginx-selfsigned.crt --from-file=nginx-selfsigned.key --namespace=ipchecker

```

## Third set up the nginx configuration

This file set up the paramethers of the reverse proxy server

```bash
kubectl apply -f nginx-config.yml
```

## Fourth deploy nginx

This is the file that set up the image, replicas, cmd to run when deploying a pod, secrets and the container pod that the application will use

```bash
kubectl apply -f nginx_deployment.yml
```

## Fifth apply the nginx service file

This file that allows the pods to receives a cluster-internal IP address and a nodeport, making it not only accessible from within the cluster but also from the outside. Similar to port forward.

A NodePort service builds on top of the ClusterIP service, exposing it to a port accessible from outside the cluster.

```bash
kubectl apply -f nginx_service.yml
```

## Sixth and final we set up the nginx autoscaler policies

This file sets up the policies where the pods will be scaled up or down

```bash
kubectl apply -f nginx_hpa.yml
```