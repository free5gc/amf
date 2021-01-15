/*
 * AMF Configuration Factory
 */

package factory

import (
	"free5gc/lib/openapi/models"
	"free5gc/src/amf/context"
)

type Config struct {
	Info *Info `yaml:"info"`

	Configuration *Configuration `yaml:"configuration"`
}

type Info struct {
	Version string `yaml:"version,omitempty"`

	Description string `yaml:"description,omitempty"`
}

type Configuration struct {
	AmfName string `yaml:"amfName,omitempty"`

	NgapIpList []string `yaml:"ngapIpList,omitempty"`

	Sbi *Sbi `yaml:"sbi,omitempty"`

	ServiceNameList []string `yaml:"serviceNameList,omitempty"`

	ServedGumaiList []models.Guami `yaml:"servedGuamiList,omitempty"`

	SupportTAIList []models.Tai `yaml:"supportTaiList,omitempty"`

	PlmnSupportList []context.PlmnSupportItem `yaml:"plmnSupportList,omitempty"`

	SupportDnnList []string `yaml:"supportDnnList,omitempty"`

	NrfUri string `yaml:"nrfUri,omitempty"`

	Security *Security `yaml:"security,omitempty"`

	NetworkName context.NetworkName `yaml:"networkName,omitempty"`

	T3502 int `yaml:"t3502,omitempty"`

	T3512 int `yaml:"t3512,omitempty"`

	Non3gppDeregistrationTimer int `yaml:"mon3gppDeregistrationTimer,omitempty"`
}

type Sbi struct {
	Scheme       string `yaml:"scheme"`
	RegisterIPv4 string `yaml:"registerIPv4,omitempty"` // IP that is registered at NRF.
	// IPv6Addr string `yaml:"ipv6Addr,omitempty"`
	BindingIPv4 string `yaml:"bindingIPv4,omitempty"` // IP used to run the server in the node.
	Port        int    `yaml:"port,omitempty"`
}

type Security struct {
	IntegrityOrder []string `yaml:"integrityOrder,omitempty"`
	CipheringOrder []string `yaml:"cipheringOrder,omitempty"`
}
