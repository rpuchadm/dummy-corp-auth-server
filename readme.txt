cargo new dummy-corp-auth-server

cargo update

#Makefile
docker build -t rust-app .
docker tag rust-app localhost:32000/dummy-corp-auth-app:latest
docker push localhost:32000/dummy-corp-auth-app:latest
microk8s kubectl rollout restart deploy dummy-corp-auth-app -n dummy-corp-erp-namespace

sudo vim /etc/hosts
127.0.0.1       crm.mydomain.com


cargo build &&\
cp -v target/debug/dummy-corp-auth-server docker/ &&\
cp -v Rocket.toml docker/ &&\
cd docker &&\
docker build -t rust-app -f DockerfileDebug . &&\
docker tag rust-app localhost:32000/dummy-corp-auth-app:latest &&\
docker push localhost:32000/dummy-corp-auth-app:latest &&\
microk8s kubectl rollout restart deploy dummy-corp-auth-app -n dummy-corp-erp-namespace
cd ..


# desde el pod
curl http://localhost:8000/status
# ip del pod
curl http://10.1.69.40:8000/status
# ip del servicio
microk8s kubectl get services -n dummy-crm-namespace | grep dummy-crm
curl http://10.152.183.94:8000/status
# nombre del servicio corto
curl http://dummy-crm-rust-app-service:8000/status
# nombre del servicio largo
curl http://dummy-crm-rust-app-service.dummy-crm-namespace.svc.cluster.local:8000/status
# desde fuera
curl -k https://crm.mydomain.com/crm/status
# desde el clúster
microk8s kubectl run curlpod --image=curlimages/curl:latest -it --rm -- /bin/sh
curl http://dummy-crm-rust-app-service:8000/status