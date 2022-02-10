/*
 * AMF Configuration Factory
 */

package factory

import (
	"fmt"
	"time"

	"github.com/asaskevich/govalidator"

	"github.com/free5gc/openapi/models"
	logger_util "github.com/free5gc/util/logger"
)

const (
	AMF_EXPECTED_CONFIG_VERSION = "1.0.3"
	AMF_DEFAULT_IPV4            = "127.0.0.18"
	AMF_DEFAULT_PORT            = "8000"
	AMF_DEFAULT_PORT_INT        = 8000
	AMF_DEFAULT_NRFURI          = "https://127.0.0.10:8000"
)

type Config struct {
	Info          *Info               `yaml:"info" valid:"required"`
	Configuration *Configuration      `yaml:"configuration" valid:"required"`
	Logger        *logger_util.Logger `yaml:"logger" valid:"required"`
}

func (c *Config) Validate() (bool, error) {
	info := c.Info
	if _, err := info.validate(); err != nil {
		return false, err
	}

	Configuration := c.Configuration
	if _, err := Configuration.validate(); err != nil {
		return false, err
	}

	Logger := c.Logger
	if _, err := Logger.Validate(); err != nil {
		return false, err
	}

	if _, err := govalidator.ValidateStruct(c); err != nil {
		return false, appendInvalid(err)
	}

	return true, nil
}

type Info struct {
	Version     string `yaml:"version,omitempty" valid:"required"`
	Description string `yaml:"description,omitempty" valid:"-"`
}

func (i *Info) validate() (bool, error) {
	if _, err := govalidator.ValidateStruct(i); err != nil {
		return false, appendInvalid(err)
	}

	return true, nil
}

type Configuration struct {
	AmfName                         string                    `yaml:"amfName,omitempty" valid:"required, type(string)"`
	NgapIpList                      []string                  `yaml:"ngapIpList,omitempty" valid:"required"`
	Sbi                             *Sbi                      `yaml:"sbi,omitempty" valid:"required"`
	NetworkFeatureSupport5GS        *NetworkFeatureSupport5GS `yaml:"networkFeatureSupport5GS,omitempty" valid:"optional"`
	ServiceNameList                 []string                  `yaml:"serviceNameList,omitempty" valid:"required"`
	ServedGumaiList                 []models.Guami            `yaml:"servedGuamiList,omitempty" valid:"required"`
	SupportTAIList                  []models.Tai              `yaml:"supportTaiList,omitempty" valid:"required"`
	PlmnSupportList                 []PlmnSupportItem         `yaml:"plmnSupportList,omitempty" valid:"required"`
	SupportDnnList                  []string                  `yaml:"supportDnnList,omitempty" valid:"required"`
	NrfUri                          string                    `yaml:"nrfUri,omitempty" valid:"required, url"`
	Security                        *Security                 `yaml:"security,omitempty" valid:"required"`
	NetworkName                     NetworkName               `yaml:"networkName,omitempty" valid:"required"`
	T3502Value                      int                       `yaml:"t3502Value,omitempty" valid:"required, type(int)"`
	T3512Value                      int                       `yaml:"t3512Value,omitempty" valid:"required, type(int)"`
	Non3gppDeregistrationTimerValue int                       `yaml:"non3gppDeregistrationTimerValue,omitempty" valid:"-"`
	T3513                           TimerValue                `yaml:"t3513" valid:"required"`
	T3522                           TimerValue                `yaml:"t3522" valid:"required"`
	T3550                           TimerValue                `yaml:"t3550" valid:"required"`
	T3560                           TimerValue                `yaml:"t3560" valid:"required"`
	T3565                           TimerValue                `yaml:"t3565" valid:"required"`
	T3570                           TimerValue                `yaml:"t3570" valid:"required"`
	Locality                        string                    `yaml:"locality,omitempty" valid:"type(string),optional"`
}

func (c *Configuration) validate() (bool, error) {
	if c.NgapIpList != nil {
		var errs govalidator.Errors
		for _, v := range c.NgapIpList {
			if result := govalidator.IsHost(v); !result {
				err := fmt.Errorf("Invalid NgapIpList: %s, value should be in the form of IP", v)
				errs = append(errs, err)
			}
		}
		if len(errs) > 0 {
			return false, error(errs)
		}
	}

	if c.Sbi != nil {
		if _, err := c.Sbi.validate(); err != nil {
			return false, err
		}
	}

	if c.NetworkFeatureSupport5GS != nil {
		if _, err := c.NetworkFeatureSupport5GS.validate(); err != nil {
			return false, err
		}
	}

	if c.ServiceNameList != nil {
		var errs govalidator.Errors
		for _, v := range c.ServiceNameList {
			if v != "namf-comm" && v != "namf-evts" && v != "namf-mt" && v != "namf-loc" && v != "namf-oam" {
				err := fmt.Errorf("Invalid ServiceNameList: %s,"+
					" value should be namf-comm or namf-evts or namf-mt or namf-loc or namf-oam", v)
				errs = append(errs, err)
			}
		}
		if len(errs) > 0 {
			return false, error(errs)
		}
	}

	if c.ServedGumaiList != nil {
		var errs govalidator.Errors
		for _, v := range c.ServedGumaiList {
			if v.PlmnId == nil {
				return false, fmt.Errorf("ServedGumaiList: PlmnId is nil")
			}
			mcc := v.PlmnId.Mcc
			if result := govalidator.StringMatches(mcc, "^[0-9]{3}$"); !result {
				err := fmt.Errorf("Invalid mcc: %s, should be a 3-digit number", mcc)
				errs = append(errs, err)
			}

			mnc := v.PlmnId.Mnc
			if result := govalidator.StringMatches(mnc, "^[0-9]{2,3}$"); !result {
				err := fmt.Errorf("Invalid mnc: %s, should be a 2 or 3-digit number", mnc)
				errs = append(errs, err)
			}

			amfId := v.AmfId
			if result := govalidator.StringMatches(amfId, "^[A-Fa-f0-9]{6}$"); !result {
				err := fmt.Errorf("Invalid amfId: %s,"+
					" should be 3 bytes hex string, range: 000000~FFFFFF", amfId)
				errs = append(errs, err)
			}
		}
		if len(errs) > 0 {
			return false, error(errs)
		}
	}

	if c.SupportTAIList != nil {
		var errs govalidator.Errors
		for _, v := range c.SupportTAIList {
			if v.PlmnId == nil {
				return false, fmt.Errorf("SupportTAIList: PlmnId is nil")
			}
			mcc := v.PlmnId.Mcc
			if result := govalidator.StringMatches(mcc, "^[0-9]{3}$"); !result {
				err := fmt.Errorf("Invalid mcc: %s, should be a 3-digit number", mcc)
				errs = append(errs, err)
			}

			mnc := v.PlmnId.Mnc
			if result := govalidator.StringMatches(mnc, "^[0-9]{2,3}$"); !result {
				err := fmt.Errorf("Invalid mnc: %s, should be a 2 or 3-digit number", mnc)
				errs = append(errs, err)
			}

			tac := v.Tac
			if result := govalidator.InRangeInt(tac, 0, 16777215); !result {
				err := fmt.Errorf("Invalid tac: %s, should be in the range of 0~16777215", tac)
				errs = append(errs, err)
			}
		}
		if len(errs) > 0 {
			return false, error(errs)
		}
	}

	if c.PlmnSupportList != nil {
		var errs govalidator.Errors
		for _, v := range c.PlmnSupportList {
			if _, err := v.validate(); err != nil {
				errs = append(errs, err)
			}
		}
		if len(errs) > 0 {
			return false, error(errs)
		}
	}

	if c.Security != nil {
		if _, err := c.Security.validate(); err != nil {
			return false, err
		}
	}

	if n3gppVal := &(c.Non3gppDeregistrationTimerValue); n3gppVal == nil {
		err := fmt.Errorf("Invalid Non3gppDeregistrationTimerValue: value is required")
		return false, err
	}

	if _, err := c.NetworkName.validate(); err != nil {
		return false, err
	}

	if _, err := c.T3513.validate(); err != nil {
		return false, err
	}

	if _, err := c.T3522.validate(); err != nil {
		return false, err
	}

	if _, err := c.T3550.validate(); err != nil {
		return false, err
	}

	if _, err := c.T3560.validate(); err != nil {
		return false, err
	}

	if _, err := c.T3565.validate(); err != nil {
		return false, err
	}

	if _, err := c.T3570.validate(); err != nil {
		return false, err
	}

	if _, err := govalidator.ValidateStruct(c); err != nil {
		return false, appendInvalid(err)
	}

	return true, nil
}

func (c *Configuration) Get5gsNwFeatSuppEnable() bool {
	if c.NetworkFeatureSupport5GS != nil {
		return c.NetworkFeatureSupport5GS.Enable
	}
	return true
}

func (c *Configuration) Get5gsNwFeatSuppImsVoPS() uint8 {
	if c.NetworkFeatureSupport5GS != nil {
		return c.NetworkFeatureSupport5GS.ImsVoPS
	}
	return 0
}

func (c *Configuration) Get5gsNwFeatSuppEmc() uint8 {
	if c.NetworkFeatureSupport5GS != nil {
		return c.NetworkFeatureSupport5GS.Emc
	}
	return 0
}

func (c *Configuration) Get5gsNwFeatSuppEmf() uint8 {
	if c.NetworkFeatureSupport5GS != nil {
		return c.NetworkFeatureSupport5GS.Emf
	}
	return 0
}

func (c *Configuration) Get5gsNwFeatSuppIwkN26() uint8 {
	if c.NetworkFeatureSupport5GS != nil {
		return c.NetworkFeatureSupport5GS.IwkN26
	}
	return 0
}

func (c *Configuration) Get5gsNwFeatSuppMpsi() uint8 {
	if c.NetworkFeatureSupport5GS != nil {
		return c.NetworkFeatureSupport5GS.Mpsi
	}
	return 0
}

func (c *Configuration) Get5gsNwFeatSuppEmcN3() uint8 {
	if c.NetworkFeatureSupport5GS != nil {
		return c.NetworkFeatureSupport5GS.EmcN3
	}
	return 0
}

func (c *Configuration) Get5gsNwFeatSuppMcsi() uint8 {
	if c.NetworkFeatureSupport5GS != nil {
		return c.NetworkFeatureSupport5GS.Mcsi
	}
	return 0
}

type NetworkFeatureSupport5GS struct {
	Enable  bool  `yaml:"enable" valid:"type(bool)"`
	Length  uint8 `yaml:"length" valid:"type(uint8)"`
	ImsVoPS uint8 `yaml:"imsVoPS" valid:"type(uint8)"`
	Emc     uint8 `yaml:"emc" valid:"type(uint8)"`
	Emf     uint8 `yaml:"emf" valid:"type(uint8)"`
	IwkN26  uint8 `yaml:"iwkN26" valid:"type(uint8)"`
	Mpsi    uint8 `yaml:"mpsi" valid:"type(uint8)"`
	EmcN3   uint8 `yaml:"emcN3" valid:"type(uint8)"`
	Mcsi    uint8 `yaml:"mcsi" valid:"type(uint8)"`
}

func (f *NetworkFeatureSupport5GS) validate() (bool, error) {
	var errs govalidator.Errors

	if result := govalidator.InRangeInt(f.Length, 1, 3); !result {
		err := fmt.Errorf("Invalid length: %d, should be in the range of 1~3", f.Length)
		errs = append(errs, err)
	}
	if result := govalidator.InRangeInt(f.ImsVoPS, 0, 1); !result {
		err := fmt.Errorf("Invalid imsVoPS: %d, should be in the range of 0~1", f.ImsVoPS)
		errs = append(errs, err)
	}
	if result := govalidator.InRangeInt(f.Emc, 0, 3); !result {
		err := fmt.Errorf("Invalid emc: %d, should be in the range of 0~3", f.Emc)
		errs = append(errs, err)
	}
	if result := govalidator.InRangeInt(f.Emf, 0, 3); !result {
		err := fmt.Errorf("Invalid emf: %d, should be in the range of 0~3", f.Emf)
		errs = append(errs, err)
	}
	if result := govalidator.InRangeInt(f.IwkN26, 0, 1); !result {
		err := fmt.Errorf("Invalid iwkN26: %d, should be in the range of 0~1", f.IwkN26)
		errs = append(errs, err)
	}
	if result := govalidator.InRangeInt(f.Mpsi, 0, 1); !result {
		err := fmt.Errorf("Invalid mpsi: %d, should be in the range of 0~1", f.Mpsi)
		errs = append(errs, err)
	}
	if result := govalidator.InRangeInt(f.EmcN3, 0, 1); !result {
		err := fmt.Errorf("Invalid emcN3: %d, should be in the range of 0~1", f.EmcN3)
		errs = append(errs, err)
	}
	if result := govalidator.InRangeInt(f.Mcsi, 0, 1); !result {
		err := fmt.Errorf("Invalid mcsi: %d, should be in the range of 0~1", f.Mcsi)
		errs = append(errs, err)
	}
	if _, err := govalidator.ValidateStruct(f); err != nil {
		return false, appendInvalid(err)
	}

	if len(errs) > 0 {
		return false, error(errs)
	}

	return true, nil
}

type Sbi struct {
	Scheme       string `yaml:"scheme" valid:"required,scheme"`
	RegisterIPv4 string `yaml:"registerIPv4,omitempty" valid:"required,host"` // IP that is registered at NRF.
	BindingIPv4  string `yaml:"bindingIPv4,omitempty" valid:"required,host"`  // IP used to run the server in the node.
	Port         int    `yaml:"port,omitempty" valid:"required,port"`
	Tls          *Tls   `yaml:"tls,omitempty" valid:"optional"`
}

func (s *Sbi) validate() (bool, error) {
	govalidator.TagMap["scheme"] = govalidator.Validator(func(str string) bool {
		return str == "https" || str == "http"
	})

	if tls := s.Tls; tls != nil {
		if result, err := tls.validate(); err != nil {
			return result, err
		}
	}

	if _, err := govalidator.ValidateStruct(s); err != nil {
		return false, appendInvalid(err)
	}

	return true, nil
}

type Tls struct {
	Pem string `yaml:"pem,omitempty" valid:"type(string),minstringlength(1),required"`
	Key string `yaml:"key,omitempty" valid:"type(string),minstringlength(1),required"`
}

func (t *Tls) validate() (bool, error) {
	result, err := govalidator.ValidateStruct(t)
	return result, err
}

type Security struct {
	IntegrityOrder []string `yaml:"integrityOrder,omitempty" valid:"-"`
	CipheringOrder []string `yaml:"cipheringOrder,omitempty" valid:"-"`
}

func (s *Security) validate() (bool, error) {
	var errs govalidator.Errors

	if s.IntegrityOrder != nil {
		for _, val := range s.IntegrityOrder {
			if result := govalidator.Contains(val, "NIA"); !result {
				err := fmt.Errorf("Invalid integrityOrder: %s, should be NIA-series integrity algorithms", val)
				errs = append(errs, err)
			}
		}
	}
	if s.CipheringOrder != nil {
		for _, val := range s.CipheringOrder {
			if result := govalidator.Contains(val, "NEA"); !result {
				err := fmt.Errorf("Invalid cipheringOrder: %s, should be NEA-series ciphering algorithms", val)
				errs = append(errs, err)
			}
		}
	}

	if len(errs) > 0 {
		return false, error(errs)
	}

	return true, nil
}

type PlmnSupportItem struct {
	PlmnId     *models.PlmnId  `yaml:"plmnId" valid:"required"`
	SNssaiList []models.Snssai `yaml:"snssaiList,omitempty" valid:"required"`
}

func (p *PlmnSupportItem) validate() (bool, error) {
	var errs govalidator.Errors

	if _, err := govalidator.ValidateStruct(p); err != nil {
		return false, appendInvalid(err)
	}

	mcc := p.PlmnId.Mcc
	if result := govalidator.StringMatches(mcc, "^[0-9]{3}$"); !result {
		err := fmt.Errorf("Invalid mcc: %s, should be a 3-digit number", mcc)
		errs = append(errs, err)
	}

	mnc := p.PlmnId.Mnc
	if result := govalidator.StringMatches(mnc, "^[0-9]{2,3}$"); !result {
		err := fmt.Errorf("Invalid mnc: %s, should be a 2 or 3-digit number", mnc)
		errs = append(errs, err)
	}

	for _, snssai := range p.SNssaiList {
		sst := snssai.Sst
		sd := snssai.Sd
		if result := govalidator.InRangeInt(sst, 0, 255); !result {
			err := fmt.Errorf("Invalid sst: %d, should be in the range of 0~255", sst)
			errs = append(errs, err)
		}
		if result := govalidator.StringMatches(sd, "^[A-Fa-f0-9]{6}$"); !result {
			err := fmt.Errorf("Invalid sd: %s, should be 3 bytes hex string, range: 000000~FFFFFF", sd)
			errs = append(errs, err)
		}
	}

	if len(errs) > 0 {
		return false, error(errs)
	}

	return true, nil
}

type NetworkName struct {
	Full  string `yaml:"full" valid:"type(string)"`
	Short string `yaml:"short,omitempty" valid:"type(string)"`
}

func (n *NetworkName) validate() (bool, error) {
	if _, err := govalidator.ValidateStruct(n); err != nil {
		return false, appendInvalid(err)
	}

	return true, nil
}

type TimerValue struct {
	Enable        bool          `yaml:"enable" valid:"type(bool)"`
	ExpireTime    time.Duration `yaml:"expireTime" valid:"type(time.Duration)"`
	MaxRetryTimes int           `yaml:"maxRetryTimes,omitempty" valid:"type(int)"`
}

func (t *TimerValue) validate() (bool, error) {
	if _, err := govalidator.ValidateStruct(t); err != nil {
		return false, appendInvalid(err)
	}

	return true, nil
}

func appendInvalid(err error) error {
	var errs govalidator.Errors

	es := err.(govalidator.Errors).Errors()
	for _, e := range es {
		errs = append(errs, fmt.Errorf("Invalid %w", e))
	}

	return error(errs)
}

func (c *Config) GetVersion() string {
	if c.Info != nil && c.Info.Version != "" {
		return c.Info.Version
	}
	return ""
}
