/*
Copyright IBM Corp. 2017 All Rights Reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

		 http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package mgmt

import (
    "sync"

    "errors"

    "github.com/ssor/fabric_msp/bccsp/factory"
    "github.com/ssor/fabric_msp/msp"
    "github.com/ssor/zlog"
)

// LoadLocalMsp loads the local MSP from the specified directory
func LoadLocalMsp(dir string, bccspConfig *factory.FactoryOpts, mspID string) error {
    if mspID == "" {
        return errors.New("The local MSP must have an ID")
    }

    conf, err := msp.GetLocalMspConfig(mspID, dir, bccspConfig)
    if err != nil {
        return err
    }

    return GetLocalMSP().Setup(conf)
}

// FIXME: AS SOON AS THE CHAIN MANAGEMENT CODE IS COMPLETE,
// THESE MAPS AND HELPSER FUNCTIONS SHOULD DISAPPEAR BECAUSE
// OWNERSHIP OF PER-CHAIN MSP MANAGERS WILL BE HANDLED BY IT;
// HOWEVER IN THE INTERIM, THESE HELPER FUNCTIONS ARE REQUIRED
var (
    m        sync.Mutex
    localMsp msp.MSP
    mspMap   = make(map[string]msp.MSPManager)

    mspLogger = zlog.New("fabric_msp", "msp")
)

// GetManagerForChain returns the msp manager for the supplied
// chain; if no such manager exists, one is created
func GetManagerForChain(chainID string) msp.MSPManager {
    m.Lock()
    defer m.Unlock()

    mspMgr, ok := mspMap[chainID]
    if !ok {
        mspLogger.Debugf("Created new msp manager for chain %s", chainID)
        mspMgr = msp.NewMSPManager()
        mspMap[chainID] = mspMgr
    }
    return mspMgr
}

// GetManagers returns all the managers registered
func GetDeserializers() map[string]msp.IdentityDeserializer {
    m.Lock()
    defer m.Unlock()

    clone := make(map[string]msp.IdentityDeserializer)
    for key, mspManager := range mspMap {
        clone[key] = mspManager
    }

    return clone
}

// XXXSetMSPManager is a stopgap solution to transition from the custom MSP config block
// parsing to the configtx.Manager interface, while preserving the problematic singleton
// nature of the MSP manager
func XXXSetMSPManager(chainID string, manager msp.MSPManager) {
    m.Lock()
    defer m.Unlock()

    mspMap[chainID] = manager
}

// GetLocalMSP returns the local msp (and creates it if it doesn't exist)
func GetLocalMSP() msp.MSP {
    var lclMsp msp.MSP
    var created bool = false
    {
        m.Lock()
        defer m.Unlock()

        lclMsp = localMsp
        if lclMsp == nil {
            var err error
            created = true
            lclMsp, err = msp.NewBccspMsp()
            if err != nil {
                mspLogger.Fatalf("Failed to initialize local MSP, received err %s", err)
            }
            localMsp = lclMsp
        }
    }

    if created {
        mspLogger.Debugf("Created new local MSP")
    } else {
        mspLogger.Debugf("Returning existing local MSP")
    }

    return lclMsp
}

// GetIdentityDeserializer returns the IdentityDeserializer for the given chain
func GetIdentityDeserializer(chainID string) msp.IdentityDeserializer {
    if chainID == "" {
        return GetLocalMSP()
    }

    return GetManagerForChain(chainID)
}

// GetLocalSigningIdentityOrPanic returns the local signing identity or panic in case
// or error
func GetLocalSigningIdentityOrPanic() msp.SigningIdentity {
    id, err := GetLocalMSP().GetDefaultSigningIdentity()
    if err != nil {
        mspLogger.Panicf("Failed getting local signing identity [%s]", err)
    }
    return id
}
