# Configuration Manager with openconfigd

`cfgmgr` branch add support of configuration manager with `openconfigd`. It
added YANG based configuration schema and cli based configuration.

## openconfigd

We need to install `openconfigd` from
https://github.com/coreswitch/openconfigd/. Please clone the repository then
checkout `free5gc` branch.

``` shell
$ mkdir -p ${GOPATH}/src/github.com/coreswitch
$ cd ${GOPATH}/src/github.com/coreswitch
$ git clone https://github.com/coreswitch/openconfigd.git
$ cd openconfigd
$ git checkout free5gc
$ GO111MODULE=off go get github.com/coreswitch/openconfigd/openconfigd
$ GO111MODULE=off go get github.com/coreswitch/openconfigd/cli_command
``

We might need to build `cli` command and install `/etc/bash_completoin.d/cli`.  Please refer to openconfigd document.

## AMF

As a first example, this branch has changes against to AMF.  Please apply following changes to free5gc/Makefile.

``` patch
diff --git a/Makefile b/Makefile
index 02e25c9..7f1df73 100644
--- a/Makefile
+++ b/Makefile
@@ -44,7 +44,7 @@ $(GO_BIN_PATH)/%: $(NF_GO_FILES)
 # $(@F): The file-within-directory part of the file name of the target.
 	@echo "Start building $(@F)...."
 	cd $(GO_SRC_PATH)/$(@F)/cmd && \
-	CGO_ENABLED=0 go build -gcflags "$(GCFLAGS)" -ldflags "$(LDFLAGS)" -o $(ROOT_PATH)/$@ main.go
+	CGO_ENABLED=0 go build $(TAGS) -gcflags "$(GCFLAGS)" -ldflags "$(LDFLAGS)" -o $(ROOT_PATH)/$@ main.go
 
 vpath %.go $(addprefix $(GO_SRC_PATH)/, $(GO_NF))
 
```

We can build cfgmgr enabled version by:

``` shell
$ TAGS="-tags cfgmgr" make
```

Once AMF is properly build.  We are ready to go.

## Lanching openconfigd and free5gc

Please start `openconfigd` before starting AMF. Once both openconfigd and
free5gc is started. We can configure AMF from openconfigd cli.

``` shell
$ cli
> configure
# set amf name "AMF"
# commit
# show
amf {
    name "AMF";
}
```

Following is sample configuration of AMF.

``` shell
set amf name "AMF"
set amf network-feature-support-5gs emc 0
set amf network-feature-support-5gs emc-n3 0
set amf network-feature-support-5gs emf 0
set amf network-feature-support-5gs enable true
set amf network-feature-support-5gs ims-vops 0
set amf network-feature-support-5gs iwk-n26 0
set amf network-feature-support-5gs length 1
set amf network-feature-support-5gs mpsi 0
set amf network-name full "free5GC"
set amf network-name short "free"
set amf ngap-ip-list 10.211.55.65
set amf non3gpp-deregistration-timer-value 3240
set amf plmn-support-list 1
set amf plmn-support-list 1 plmnid mcc 208
set amf plmn-support-list 1 plmnid mnc 93
set amf plmn-support-list 1 snssai-list 1
set amf plmn-support-list 1 snssai-list 1 sd 010203
set amf plmn-support-list 1 snssai-list 1 sst 1
set amf plmn-support-list 1 snssai-list 2
set amf plmn-support-list 1 snssai-list 2 sd 112233
set amf plmn-support-list 1 snssai-list 2 sst 1
set amf sbi binding-ipv4 127.0.0.18
set amf sbi port 8000
set amf sbi register-ipv4 127.0.0.18
set amf sbi scheme http
set amf sbi tls key "config/TLS/amf.key"
set amf sbi tls pem "config/TLS/amf.pem"
set amf security ciphering-order NEA0
set amf security integrity-order NIA2
set amf served-guami-list 1
set amf served-guami-list 1 amfid "cafe00"
set amf served-guami-list 1 plmnid mcc 208
set amf served-guami-list 1 plmnid mnc 93
set amf service-name-list namf-comm
set amf service-name-list namf-evts
set amf service-name-list namf-loc
set amf service-name-list namf-mt
set amf service-name-list namf-oam
set amf support-dnn-list internet
set amf support-tai-list 1
set amf support-tai-list 1 plmnid mcc 208
set amf support-tai-list 1 plmnid mnc 93
set amf support-tai-list 1 tac "1"
set amf t3502-value 720
set amf t3512-value 3600
set amf t3513 enable true
set amf t3513 expire-time 6
set amf t3513 max-retry-times 4
set amf t3522 enable true
set amf t3522 expire-time 6
set amf t3522 max-retry-times 4
set amf t3550 enable true
set amf t3550 expire-time 6
set amf t3550 max-retry-times 4
set amf t3560 enable true
set amf t3560 expire-time 6
set amf t3560 max-retry-times 4
set amf t3565 enable true
set amf t3565 expire-time 6
set amf t3565 max-retry-times 4
set amf t3570 enable true
set amf t3570 expire-time 6
set amf t3570 max-retry-times 4
set nrf-uri "http://127.0.0.10:8000"
```
