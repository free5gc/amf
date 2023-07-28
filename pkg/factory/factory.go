/*
 * AMF Configuration Factory
 */

package factory

import (
	"fmt"
	"io/ioutil"
	"strings"

	"github.com/asaskevich/govalidator"
	"gopkg.in/yaml.v2"

	"github.com/free5gc/amf/internal/logger"
)

var AmfConfig *Config

// TODO: Support configuration update from REST api
func InitConfigFactory(f string, cfg *Config) error {
	if f == "" {
		// Use default config path
		f = AmfDefaultConfigPath
	}

	if content, err := ioutil.ReadFile(f); err != nil {
		return fmt.Errorf("[Factory] %+v", err)
	} else {
		logger.CfgLog.Infof("Read config from [%s]", f)
		if yamlErr := yaml.Unmarshal(content, cfg); yamlErr != nil {
			return fmt.Errorf("[Factory] %+v", yamlErr)
		}
	}

	//change sd to lowercase
	PlmnSupportList := cfg.Configuration.PlmnSupportList
	for i := range PlmnSupportList {
		SNssaiList := PlmnSupportList[i].SNssaiList
		for j := range SNssaiList {
			SNssaiList[j].Sd = strings.ToLower(SNssaiList[j].Sd)
		}
	}

	return nil
}

func ReadConfig(cfgPath string) (*Config, error) {
	cfg := &Config{}
	if err := InitConfigFactory(cfgPath, cfg); err != nil {
		return nil, fmt.Errorf("ReadConfig [%s] Error: %+v", cfgPath, err)
	}
	if _, err := cfg.Validate(); err != nil {
		validErrs := err.(govalidator.Errors).Errors()
		for _, validErr := range validErrs {
			logger.CfgLog.Errorf("%+v", validErr)
		}
		logger.CfgLog.Errorf("[-- PLEASE REFER TO SAMPLE CONFIG FILE COMMENTS --]")
		return nil, fmt.Errorf("Config validate Error")
	}

	return cfg, nil
}
