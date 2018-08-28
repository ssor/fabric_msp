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

package msp

import (
    "fmt"
    "io/ioutil"

    "github.com/golang/protobuf/proto"

    "encoding/pem"
    "path/filepath"

    "os"

    "github.com/ssor/fabric_msp/bccsp"
    "github.com/ssor/fabric_msp/bccsp/factory"
    "github.com/ssor/fabric_msp/protos/msp"
    "gopkg.in/yaml.v2"
    "path"
)

type OrganizationalUnitIdentifiersConfiguration struct {
    Certificate                  string `yaml:"Certificate,omitempty"`
    OrganizationalUnitIdentifier string `yaml:"OrganizationalUnitIdentifier,omitempty"`
}

type Configuration struct {
    OrganizationalUnitIdentifiers []*OrganizationalUnitIdentifiersConfiguration `yaml:"OrganizationalUnitIdentifiers,omitempty"`
}

func readFile(file string) ([]byte, error) {
    fileCont, err := ioutil.ReadFile(file)
    if err != nil {
        return nil, fmt.Errorf("could not read file %s, err %s", file, err)
    }

    return fileCont, nil
}

// return content of file, and before return, check the file has pem content
func readPemFile(file string) ([]byte, error) {
    ext := path.Ext(file)
    if ext != ".pem" {
        return nil, fmt.Errorf("%s is not a pem file", file)
    }

    bytes, err := readFile(file)
    if err != nil {
        return nil, err
    }

    b, _ := pem.Decode(bytes)
    if b == nil { // TODO: also check that the type is what we expect (cert vs key..)
        return nil, fmt.Errorf("no pem content for file %s", file)
    }

    return bytes, nil
}

func getPemMaterialFromDir(dir string) ([][]byte, error) {
    mspLogger.Debugf("Reading directory %s", dir)

    _, err := os.Stat(dir)
    if os.IsNotExist(err) {
        return nil, err
    }

    content := make([][]byte, 0)
    files, err := ioutil.ReadDir(dir)
    if err != nil {
        return nil, fmt.Errorf("could not read directory %s, err %s", err, dir)
    }

    for _, f := range files {
        if f.IsDir() {
            continue
        }

        fullName := filepath.Join(dir, string(filepath.Separator), f.Name())
        mspLogger.Debugf("Inspecting file %s", fullName)

        item, err := readPemFile(fullName)
        if err != nil {
            mspLogger.Warningf("Failed readgin file %s: %s", fullName, err)
            continue
        }

        content = append(content, item)
    }

    return content, nil
}

const (
    cacerts              = "cacerts"
    admincerts           = "admincerts"
    signcerts            = "signcerts"
    keystore             = "keystore"
    intermediatecerts    = "intermediatecerts"
    crlsfolder           = "crls"
    configfilename       = "config.yaml"
    tlscacerts           = "tlscacerts"
    tlsintermediatecerts = "tlsintermediatecerts"
)

func SetupBCCSPKeystoreConfig(bccspConfig *factory.FactoryOpts, keystoreDir string) *factory.FactoryOpts {
    if bccspConfig == nil {
        bccspConfig = factory.GetDefaultOpts()
    }

    if bccspConfig.ProviderName == "SW" {
        if bccspConfig.SwOpts == nil {
            bccspConfig.SwOpts = factory.GetDefaultOpts().SwOpts
        }

        // Only override the KeyStorePath if it was left empty
        if bccspConfig.SwOpts.FileKeystore == nil ||
            bccspConfig.SwOpts.FileKeystore.KeyStorePath == "" {
            bccspConfig.SwOpts.Ephemeral = false
            bccspConfig.SwOpts.FileKeystore = &factory.FileKeystoreOpts{KeyStorePath: keystoreDir}
        }
    }

    return bccspConfig
}

func GetLocalMspConfig(ID, dir string, bccspConfig *factory.FactoryOpts) (*msp.MSPConfig, error) {
    signCertsDir := filepath.Join(dir, signcerts)
    keystoreDir := filepath.Join(dir, keystore)
    bccspConfig = SetupBCCSPKeystoreConfig(bccspConfig, keystoreDir)

    err := factory.InitFactories(bccspConfig)
    if err != nil {
        return nil, fmt.Errorf("could not initialize BCCSP Factories [%s]", err)
    }

    signCerts, err := getPemMaterialFromDir(signCertsDir)
    if err != nil || len(signCerts) == 0 {
        return nil, fmt.Errorf("could not load a valid signer certificate from directory %s, err %s", signCertsDir, err)
    }

    /* FIXME: for now we're making the following assumptions
    1) there is exactly one signing cert
    2) BCCSP's KeyStore has the private key that matches SKI of
       signing cert
    */

    sigId := &msp.SigningIdentityInfo{PublicSigner: signCerts[0], PrivateSigner: nil}

    return getMspConfig(dir, ID, sigId)
}

func GetVerifyingMspConfig(dir string, ID string) (*msp.MSPConfig, error) {
    return getMspConfig(dir, ID, nil)
}

func getMspConfig(dir string, ID string, sigId *msp.SigningIdentityInfo) (*msp.MSPConfig, error) {
    caCertDir := filepath.Join(dir, cacerts)
    adminCertDir := filepath.Join(dir, admincerts)
    intermediateCertsDir := filepath.Join(dir, intermediatecerts)
    crlsDir := filepath.Join(dir, crlsfolder)
    configFile := filepath.Join(dir, configfilename)
    tlsCaCertDir := filepath.Join(dir, tlscacerts)
    tlsIntermediateCertsDir := filepath.Join(dir, tlsintermediatecerts)

    caCerts, err := getPemMaterialFromDir(caCertDir)
    if err != nil || len(caCerts) == 0 {
        return nil, fmt.Errorf("could not load a valid ca certificate from directory %s, err %s", caCertDir, err)
    }

    adminCert, err := getPemMaterialFromDir(adminCertDir)
    if err != nil || len(adminCert) == 0 {
        return nil, fmt.Errorf("could not load a valid admin certificate from directory %s, err %s", adminCertDir, err)
    }

    intermediateCerts, err := getPemMaterialFromDir(intermediateCertsDir)
    if os.IsNotExist(err) {
        mspLogger.Debugf("Intermediate certs folder not found at [%s]. Skipping. [%s]", intermediateCertsDir, err)
    } else if err != nil {
        return nil, fmt.Errorf("failed loading intermediate ca certs at [%s]: [%s]", intermediateCertsDir, err)
    }

    tlsCACerts, err := getPemMaterialFromDir(tlsCaCertDir)
    var tlsIntermediateCerts [][]byte
    if os.IsNotExist(err) {
        mspLogger.Debugf("TLS CA certs folder not found at [%s]. Skipping and ignoring TLS intermediate CA folder. [%s]", tlsIntermediateCertsDir, err)
    } else if err != nil {
        return nil, fmt.Errorf("failed loading TLS ca certs at [%s]: [%s]", tlsIntermediateCertsDir, err)
    } else if len(tlsCACerts) != 0 {
        tlsIntermediateCerts, err = getPemMaterialFromDir(tlsIntermediateCertsDir)
        if os.IsNotExist(err) {
            mspLogger.Debugf("TLS intermediate certs folder not found at [%s]. Skipping. [%s]", tlsIntermediateCertsDir, err)
        } else if err != nil {
            return nil, fmt.Errorf("failed loading TLS intermediate ca certs at [%s]: [%s]", tlsIntermediateCertsDir, err)
        }
    } else {
        mspLogger.Debugf("TLS CA certs folder at [%s] is empty. Skipping.", tlsIntermediateCertsDir)
    }

    crls, err := getPemMaterialFromDir(crlsDir)
    if os.IsNotExist(err) {
        mspLogger.Debugf("crls folder not found at [%s]. Skipping. [%s]", crlsDir, err)
    } else if err != nil {
        return nil, fmt.Errorf("failed loading crls at [%s]: [%s]", crlsDir, err)
    }

    // Load configuration file
    // if the configuration file is there then load it
    // otherwise skip it
    var ouis []*msp.FabricOUIdentifier
    _, err = os.Stat(configFile)
    if err == nil {
        // load the file, if there is a failure in loading it then
        // return an error
        raw, err := ioutil.ReadFile(configFile)
        if err != nil {
            return nil, fmt.Errorf("failed loading configuration file at [%s]: [%s]", configFile, err)
        }

        configuration := Configuration{}
        err = yaml.Unmarshal(raw, &configuration)
        if err != nil {
            return nil, fmt.Errorf("failed unmarshalling configuration file at [%s]: [%s]", configFile, err)
        }

        // Prepare OrganizationalUnitIdentifiers
        if len(configuration.OrganizationalUnitIdentifiers) > 0 {
            for _, ouID := range configuration.OrganizationalUnitIdentifiers {
                f := filepath.Join(dir, ouID.Certificate)
                raw, err = ioutil.ReadFile(f)
                if err != nil {
                    return nil, fmt.Errorf("failed loading OrganizationalUnit certificate at [%s]: [%s]", f, err)
                }
                oui := &msp.FabricOUIdentifier{
                    Certificate:                  raw,
                    OrganizationalUnitIdentifier: ouID.OrganizationalUnitIdentifier,
                }
                ouis = append(ouis, oui)
            }
        }
    } else {
        mspLogger.Warnf("MSP configuration file not found at [%s]: [%s]", configFile, err)
    }

    // Set FabricCryptoConfig
    cryptoConfig := &msp.FabricCryptoConfig{
        SignatureHashFamily:            bccsp.SHA2,
        IdentityIdentifierHashFunction: bccsp.SHA256,
    }

    // Compose FabricMSPConfig
    fabricMspConf := &msp.FabricMSPConfig{
        Admins:                        adminCert,
        RootCerts:                     caCerts,
        IntermediateCerts:             intermediateCerts,
        SigningIdentity:               sigId,
        Name:                          ID,
        OrganizationalUnitIdentifiers: ouis,
        RevocationList:                crls,
        CryptoConfig:                  cryptoConfig,
        TlsRootCerts:                  tlsCACerts,
        TlsIntermediateCerts:          tlsIntermediateCerts,
    }

    fmpsjs, _ := proto.Marshal(fabricMspConf)

    mspConf := &msp.MSPConfig{Config: fmpsjs, Type: int32(FABRIC)}

    return mspConf, nil
}
