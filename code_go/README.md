# Makefile
.PHONY: build install test clean

BINARY_NAME=hids
INSTALL_PATH=/usr/local/bin
CONFIG_PATH=/etc/hids
LOG_PATH=/var/log/hids

build:
	go build -o bin/$(BINARY_NAME) cmd/hids/main.go

install: build
	sudo mkdir -p $(CONFIG_PATH)
	sudo mkdir -p $(LOG_PATH)
	sudo cp bin/$(BINARY_NAME) $(INSTALL_PATH)/
	sudo cp configs/hids.yaml $(CONFIG_PATH)/
	sudo chmod 700 $(INSTALL_PATH)/$(BINARY_NAME)
	sudo setcap cap_sys_admin=ep $(INSTALL_PATH)/$(BINARY_NAME)

clean:
	rm -rf bin/
	go clean

uninstall:
	sudo rm -f $(INSTALL_PATH)/$(BINARY_NAME)
	sudo rm -rf $(CONFIG_PATH)
