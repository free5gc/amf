package main

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime/debug"

	"github.com/asaskevich/govalidator"
	"github.com/urfave/cli"

	"github.com/free5gc/amf/internal/logger"
	"github.com/free5gc/amf/internal/util"
	"github.com/free5gc/amf/pkg/service"
	"github.com/free5gc/util/version"
)

var AMF = &service.AMF{}

func main() {
	defer func() {
		if p := recover(); p != nil {
			// Print stack for panic to log. Fatalf() will let program exit.
			logger.AppLog.Fatalf("panic: %v\n%s", p, string(debug.Stack()))
		}
	}()

	app := cli.NewApp()
	app.Name = "amf"
	app.Usage = "5G Access and Mobility Management Function (AMF)"
	app.Action = action
	app.Flags = AMF.GetCliCmd()
	if err := app.Run(os.Args); err != nil {
		logger.AppLog.Errorf("AMF Run error: %v\n", err)
		return
	}
}

func action(c *cli.Context) error {
	if err := initLogFile(c.String("log"), c.String("log5gc")); err != nil {
		logger.AppLog.Errorf("%+v", err)
		return err
	}

	if err := AMF.Initialize(c); err != nil {
		switch err1 := err.(type) {
		case govalidator.Errors:
			errs := err1.Errors()
			for _, e := range errs {
				logger.CfgLog.Errorf("%+v", e)
			}
		default:
			logger.CfgLog.Errorf("%+v", err)
		}

		logger.CfgLog.Errorf("[-- PLEASE REFER TO SAMPLE CONFIG FILE COMMENTS --]")
		return fmt.Errorf("Failed to initialize !!")
	}

	logger.AppLog.Infoln(c.App.Name)
	logger.AppLog.Infoln("AMF version: ", version.GetVersion())

	AMF.Start()

	return nil
}

func initLogFile(logNfPath, log5gcPath string) error {
	AMF.KeyLogPath = util.AmfDefaultKeyLogPath

	if err := logger.LogFileHook(logNfPath, log5gcPath); err != nil {
		return err
	}

	if logNfPath != "" {
		nfDir, _ := filepath.Split(logNfPath)
		tmpDir := filepath.Join(nfDir, "key")
		if err := os.MkdirAll(tmpDir, 0o775); err != nil {
			logger.InitLog.Errorf("Make directory %s failed: %+v", tmpDir, err)
			return err
		}
		_, name := filepath.Split(util.AmfDefaultKeyLogPath)
		AMF.KeyLogPath = filepath.Join(tmpDir, name)
	}

	return nil
}
