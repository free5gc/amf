/*
 * AMF Configuration Factory
 */

package factory

import (
	"fmt"
	"io/ioutil"
	"time"

	"gopkg.in/yaml.v2"

	"github.com/free5gc/amf/internal/logger"
)

var AmfConfig Config

var initSyncCh chan interface{}
var cfgSyncCh chan interface{}

// TODO: Support configuration update from REST api
func InitConfigFileFactory(f string) error {
	if content, err := ioutil.ReadFile(f); err != nil {
		return err
	} else {
		AmfConfig = Config{}

		if yamlErr := yaml.Unmarshal(content, &AmfConfig); yamlErr != nil {
			return yamlErr
		}
	}

	return nil
}

func InitConfigFactory(f string, initCh chan interface{}) error {
	initSyncCh = initCh
	cfgSyncCh = make(chan interface{})

	CfgMgrStart()

	select {
	case <-cfgSyncCh:
		logger.CfgLog.Infof("cfgMgr init config done from openconfigd")
		return nil
	case <-time.After(time.Second * 2):
		logger.CfgLog.Infof("cfgMgr openconfigd timeout read config from file")
		if err := InitConfigFileFactory(f); err != nil {
			return err
		}
		if _, err := AmfConfig.Validate(); err != nil {
			return err
		}
		close(initCh)
		return nil
	}
}

func CheckConfigVersion() error {
	currentVersion := AmfConfig.GetVersion()

	if currentVersion != AMF_EXPECTED_CONFIG_VERSION {
		return fmt.Errorf("config version is [%s], but expected is [%s].",
			currentVersion, AMF_EXPECTED_CONFIG_VERSION)
	}

	logger.CfgLog.Infof("config version [%s]", currentVersion)

	return nil
}
