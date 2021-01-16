/*
 * AMF Configuration Factory
 */

package factory

import (
	"time"

	"github.com/free5gc/logger_util"
	"github.com/free5gc/openapi/models"
)

const (
	AMF_EXPECTED_CONFIG_VERSION = "1.0.0"
)

type Config struct {
	Info          *Info               `yaml:"info"`
	Configuration *Configuration      `yaml:"configuration"`
	Logger        *logger_util.Logger `yaml:"logger"`
}

type Info struct {
	Version     string `yaml:"version,omitempty"`
	Description string `yaml:"description,omitempty"`
}

const (
	AMF_DEFAULT_IPV4     = "127.0.0.18"
	AMF_DEFAULT_PORT     = "8000"
	AMF_DEFAULT_PORT_INT = 8000
	AMF_DEFAULT_NRFURI   = "https://127.0.0.10:8000"
)

type Configuration struct {
	AmfName                         string            `yaml:"amfName,omitempty"`
	NgapIpList                      []string          `yaml:"ngapIpList,omitempty"`
	Sbi                             *Sbi              `yaml:"sbi,omitempty"`
	ServiceNameList                 []string          `yaml:"serviceNameList,omitempty"`
	ServedGumaiList                 []models.Guami    `yaml:"servedGuamiList,omitempty"`
	SupportTAIList                  []models.Tai      `yaml:"supportTaiList,omitempty"`
	PlmnSupportList                 []PlmnSupportItem `yaml:"plmnSupportList,omitempty"`
	SupportDnnList                  []string          `yaml:"supportDnnList,omitempty"`
	NrfUri                          string            `yaml:"nrfUri,omitempty"`
	Security                        *Security         `yaml:"security,omitempty"`
	NetworkName                     NetworkName       `yaml:"networkName,omitempty"`
	T3502Value                      int               `yaml:"t3502Value,omitempty"`
	T3512Value                      int               `yaml:"t3512Value,omitempty"`
	Non3gppDeregistrationTimerValue int               `yaml:"non3gppDeregistrationTimerValue,omitempty"`
	T3513                           TimerValue        `yaml:"t3513"`
	T3522                           TimerValue        `yaml:"t3522"`
	T3550                           TimerValue        `yaml:"t3550"`
	T3560                           TimerValue        `yaml:"t3560"`
	T3565                           TimerValue        `yaml:"t3565"`
}

type Sbi struct {
	Scheme       string `yaml:"scheme"`
	RegisterIPv4 string `yaml:"registerIPv4,omitempty"` // IP that is registered at NRF.
	BindingIPv4  string `yaml:"bindingIPv4,omitempty"`  // IP used to run the server in the node.
	Port         int    `yaml:"port,omitempty"`
}

type Security struct {
	IntegrityOrder []string `yaml:"integrityOrder,omitempty"`
	CipheringOrder []string `yaml:"cipheringOrder,omitempty"`
}

type PlmnSupportItem struct {
	PlmnId     models.PlmnId   `yaml:"plmnId"`
	SNssaiList []models.Snssai `yaml:"snssaiList,omitempty"`
}

type NetworkName struct {
	Full  string `yaml:"full"`
	Short string `yaml:"short,omitempty"`
}

type TimerValue struct {
	Enable        bool          `yaml:"enable"`
	ExpireTime    time.Duration `yaml:"expireTime"`
	MaxRetryTimes int           `yaml:"maxRetryTimes,omitempty"`
}

func (c *Config) GetVersion() string {
	if c.Info != nil && c.Info.Version != "" {
		return c.Info.Version
	}
	return ""
}
