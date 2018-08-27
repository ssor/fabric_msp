package main

import "fmt"
import (
    "github.com/ssor/fabric_msp/msp/mgmt"
    "github.com/ssor/fabric_msp/bccsp/factory"
    "github.com/ssor/fabric_msp/config"
)

func main() {
    fmt.Println("mod")
    conf, err := config.Load("data/orderer.yaml")
    if err != nil {
        panic(err)
    }

    err = loadMsp(conf.General.LocalMSPDir, conf.General.BCCSP, conf.General.LocalMSPID)
    if err != nil {
        panic(err)
    }
}

func loadMsp(dir string, bccspConfig *factory.FactoryOpts, mspID string) error {
    err := mgmt.LoadLocalMsp(dir, bccspConfig, mspID)
    return err
}
