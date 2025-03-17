# Variables
IMAGE_NAME=rust-app
LOCAL_REGISTRY=localhost:32000
K8S_NAMESPACE=dummy-corp-erp-namespace
K8S_DEPLOYMENT=dummy-auth-rust-app

.PHONY: build tag push restart all

# Construir la imagen de Docker
build:
	docker build -t $(IMAGE_NAME) .

# Etiquetar la imagen para el registro local
tag: build
	docker tag $(IMAGE_NAME) $(LOCAL_REGISTRY)/$(K8S_DEPLOYMENT):latest

# Subir la imagen al registro local
push: tag
	docker push $(LOCAL_REGISTRY)/$(K8S_DEPLOYMENT):latest

# Reiniciar el despliegue en Kubernetes
restart:
	microk8s kubectl rollout restart deploy $(K8S_DEPLOYMENT) -n $(K8S_NAMESPACE)

# Construir, etiquetar, subir y reiniciar todo en uno
all: build tag push restart
