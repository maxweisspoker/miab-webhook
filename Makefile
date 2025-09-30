OS ?= $(shell go1.25 env GOOS)
ARCH ?= $(shell go1.25 env GOARCH)

IMAGE_NAME ?= "maxweiss/miab-webhook"
IMAGE_TAG ?= "latest"

OUT := $(shell pwd)/_out

KUBE_VERSION=1.34.1

$(shell mkdir -p "$(OUT)")
export TEST_ASSET_ETCD=_test/kubebuilder/bin/etcd
export TEST_ASSET_KUBE_APISERVER=_test/kubebuilder/bin/kube-apiserver
export TEST_ASSET_KUBECTL=_test/kubebuilder/bin/kubectl

test: _test/kubebuilder
	go1.25 test -v .

_test/kubebuilder:
	curl -fsSL https://go.kubebuilder.io/test-tools/$(KUBE_VERSION)/$(OS)/$(ARCH) -o kubebuilder-tools.tar.gz
	mkdir -p _test/kubebuilder
	tar -xvf kubebuilder-tools.tar.gz
	mv kubebuilder/bin _test/kubebuilder/
	rm -f kubebuilder-tools.tar.gz
	rm -rf kubebuilder/

clean: clean-kubebuilder

clean-kubebuilder:
	rm -rf _test/kubebuilder

build:
	docker build -t "$(IMAGE_NAME):$(IMAGE_TAG)" .

.PHONY: rendered-manifest.yaml
rendered-manifest.yaml:
	helm template miab-webhook \
        --set image.repository=$(IMAGE_NAME) \
        --set image.tag=$(IMAGE_TAG) \
        deploy > "$(OUT)/rendered-manifest.yaml"
