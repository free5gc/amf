package context

import (
       "errors"
       "net/netip"
       "os"
       "testing"

       "github.com/stretchr/testify/assert"

       "github.com/free5gc/amf/pkg/factory"
       "github.com/free5gc/openapi/models"
)

func createConfigFile(t *testing.T, postContent []byte) *os.File {
       content := []byte(`info:
  version: "1.0.9"

logger:
  level: debug

configuration:
  security:
    integrityOrder:
      - NIA2

  networkName:
    full: free5GC
    short: free

  amfName: AMF
  ngapIpList:
    - 127.0.0.19
  ngapPort: 38412

  supportDnnList:
    - internet
  nrfUri: http://127.0.0.10:8000

  serviceNameList:
    - namf-comm

  servedGuamiList:
    - plmnId:
        mcc: 208
        mnc: 93
      amfId: cafe00

  supportTaiList:
    - plmnId:
        mcc: 208
        mnc: 93
      tac: 000001

  plmnSupportList:
    - plmnId:
        mcc: 208
        mnc: 93
      snssaiList:
        - sst: 1
          sd: 010203
        - sst: 1
          sd: 112233

  t3502Value: 720
  t3512Value: 3600
  t3513:
    enable: true
  t3522:
    enable: true
  t3550:
    enable: true
  t3555:
    enable: true
  t3560:
    enable: true
  t3565:
    enable: true
  t3570:
    enable: true`)

       configFile, err := os.CreateTemp("", "")
       if err != nil {
               t.Errorf("can't create temp file: %+v", err)
       }

       if _, err = configFile.Write(content); err != nil {
               t.Errorf("can't write content of temp file: %+v", err)
       }
       if _, err = configFile.Write(postContent); err != nil {
               t.Errorf("can't write content of temp file: %+v", err)
       }
       if err = configFile.Close(); err != nil {
               t.Fatal(err)
       }
       return configFile
}

func TestInitAmfContextWithConfigIPv6(t *testing.T) {
       postContent := []byte(`

  sbi:
    scheme: http
    registerIP: 2001:db8::1:0:0:19
    bindingIP: 2001:db8::1:0:0:19
    port: 8000`)

       configFile := createConfigFile(t, postContent)

       // Test the initialization with the config file
       cfg, err := factory.ReadConfig(configFile.Name())
       if err != nil {
               t.Errorf("invalid read config: %+v %+v", err, cfg)
       }
       factory.AmfConfig = cfg

       InitAmfContext(GetSelf())

       assert.Equal(t, amfContext.SBIPort, 8000)
       assert.Equal(t, amfContext.RegisterIP.String(), "2001:db8::1:0:0:19")
       assert.Equal(t, amfContext.BindingIP.String(), "2001:db8::1:0:0:19")
       assert.Equal(t, amfContext.UriScheme, models.UriScheme("http"))

       // Close the config file
       t.Cleanup(func() {
               if err = os.RemoveAll(configFile.Name()); err != nil {
                       t.Fatal(err)
               }
       })
}

func TestInitAmfContextWithConfigIPv4(t *testing.T) {
       postContent := []byte(`
  sbi:
    scheme: http
    registerIP: "127.0.0.13"
    bindingIP: "127.0.0.13"
    port: 8131`)

       configFile := createConfigFile(t, postContent)

       // Test the initialization with the config file
       cfg, err := factory.ReadConfig(configFile.Name())
       if err != nil {
               t.Errorf("invalid read config: %+v %+v", err, cfg)
       }
       factory.AmfConfig = cfg

       InitAmfContext(GetSelf())

       assert.Equal(t, amfContext.SBIPort, 8131)
       assert.Equal(t, amfContext.RegisterIP.String(), "127.0.0.13")
       assert.Equal(t, amfContext.BindingIP.String(), "127.0.0.13")
       assert.Equal(t, amfContext.UriScheme, models.UriScheme("http"))

       // Close the config file
       t.Cleanup(func() {
               if err = os.RemoveAll(configFile.Name()); err != nil {
                       t.Fatal(err)
               }
       })
}

func TestInitAmfContextWithConfigDeprecated(t *testing.T) {
       postContent := []byte(`
  sbi:
    scheme: http
    registerIPv4: "127.0.0.30"
    bindingIPv4: "127.0.0.30"
    port: 8003`)

       configFile := createConfigFile(t, postContent)

       // Test the initialization with the config file
       cfg, err := factory.ReadConfig(configFile.Name())
       if err != nil {
               t.Errorf("invalid read config: %+v %+v", err, cfg)
       }
       factory.AmfConfig = cfg

       InitAmfContext(GetSelf())

       assert.Equal(t, amfContext.SBIPort, 8003)
       assert.Equal(t, amfContext.RegisterIP.String(), "127.0.0.30")
       assert.Equal(t, amfContext.BindingIP.String(), "127.0.0.30")
       assert.Equal(t, amfContext.UriScheme, models.UriScheme("http"))

       // Close the config file
       t.Cleanup(func() {
               if err = os.RemoveAll(configFile.Name()); err != nil {
                       t.Fatal(err)
               }
       })
}

func TestInitAmfContextWithConfigEmptySBI(t *testing.T) {
       postContent := []byte("")

       configFile := createConfigFile(t, postContent)

       // Test the initialization with the config file
       _, err := factory.ReadConfig(configFile.Name())
       assert.Equal(t, err, errors.New("Config validate Error"))

       // Close the config file
       t.Cleanup(func() {
               if err = os.RemoveAll(configFile.Name()); err != nil {
                       t.Fatal(err)
               }
       })
}

func TestInitAmfContextWithConfigMissingRegisterIP(t *testing.T) {
       postContent := []byte(`
  sbi:
    bindingIP: "2001:db8::1:0:0:130"`)

       configFile := createConfigFile(t, postContent)

       // Test the initialization with the config file
       cfg, err := factory.ReadConfig(configFile.Name())
       if err != nil {
               t.Errorf("invalid read config: %+v %+v", err, cfg)
       }
       factory.AmfConfig = cfg

       InitAmfContext(GetSelf())

       assert.Equal(t, amfContext.SBIPort, 8000)
       assert.Equal(t, amfContext.BindingIP.String(), "2001:db8::1:0:0:130")
       assert.Equal(t, amfContext.RegisterIP.String(), "2001:db8::1:0:0:130")
       assert.Equal(t, amfContext.UriScheme, models.UriScheme("https"))

       // Close the config file
       t.Cleanup(func() {
               if err = os.RemoveAll(configFile.Name()); err != nil {
                       t.Fatal(err)
               }
       })
}

func TestInitAmfContextWithConfigMissingBindingIP(t *testing.T) {
       postContent := []byte(`
  sbi:
    registerIP: "2001:db8::1:0:0:131"`)

       configFile := createConfigFile(t, postContent)

       // Test the initialization with the config file
       cfg, err := factory.ReadConfig(configFile.Name())
       if err != nil {
               t.Errorf("invalid read config: %+v %+v", err, cfg)
       }
       factory.AmfConfig = cfg

       InitAmfContext(GetSelf())

       assert.Equal(t, amfContext.SBIPort, 8000)
       assert.Equal(t, amfContext.BindingIP.String(), "2001:db8::1:0:0:131")
       assert.Equal(t, amfContext.RegisterIP.String(), "2001:db8::1:0:0:131")
       assert.Equal(t, amfContext.UriScheme, models.UriScheme("https"))

       // Close the config file
       t.Cleanup(func() {
               if err = os.RemoveAll(configFile.Name()); err != nil {
                       t.Fatal(err)
               }
       })
}

func TestInitAmfContextWithConfigIPv6FromEnv(t *testing.T) {
       postContent := []byte(`
  sbi:
    scheme: http
    registerIP: "MY_REGISTER_IP"
    bindingIP: "MY_BINDING_IP"
    port: 8313`)

       configFile := createConfigFile(t, postContent)

       if err := os.Setenv("MY_REGISTER_IP", "2001:db8::1:0:0:130"); err != nil {
               t.Errorf("Can't set MY_REGISTER_IP env")
       }
       if err := os.Setenv("MY_BINDING_IP", "2001:db8::1:0:0:130"); err != nil {
               t.Errorf("Can't set MY_BINDING_IP env")
       }

       // Test the initialization with the config file
       cfg, err := factory.ReadConfig(configFile.Name())
       if err != nil {
               t.Errorf("invalid read config: %+v %+v", err, cfg)
       }
       factory.AmfConfig = cfg

       InitAmfContext(GetSelf())

       assert.Equal(t, amfContext.SBIPort, 8313)
       assert.Equal(t, amfContext.RegisterIP.String(), "2001:db8::1:0:0:130")
       assert.Equal(t, amfContext.BindingIP.String(), "2001:db8::1:0:0:130")
       assert.Equal(t, amfContext.UriScheme, models.UriScheme("http"))

       // Close the config file
       t.Cleanup(func() {
               if err = os.RemoveAll(configFile.Name()); err != nil {
                       t.Fatal(err)
               }
       })
}

func TestResolveIPLocalhost(t *testing.T) {
       expectedAddr, err := netip.ParseAddr("::1")
       if err != nil {
               t.Errorf("invalid expected IP: %+v", expectedAddr)
       }

       addr := resolveIP("localhost")
       if addr != expectedAddr {
               t.Errorf("invalid IP: %+v", addr)
       }
       assert.Equal(t, addr, expectedAddr)
}

func TestResolveIPv4(t *testing.T) {
       expectedAddr, err := netip.ParseAddr("127.0.0.1")
       if err != nil {
               t.Errorf("invalid expected IP: %+v", expectedAddr)
       }

       addr := resolveIP("127.0.0.1")
       if addr != expectedAddr {
               t.Errorf("invalid IP: %+v", addr)
       }
}

func TestResolveIPv6(t *testing.T) {
       expectedAddr, err := netip.ParseAddr("2001:db8::1:0:0:1")
       if err != nil {
               t.Errorf("invalid expected IP: %+v", expectedAddr)
       }

       addr := resolveIP("2001:db8::1:0:0:1")
       if addr != expectedAddr {
               t.Errorf("invalid IP: %+v", addr)
       }
}
