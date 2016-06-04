/*
Copyright IBM Corp. 2016 All Rights Reserved.

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

package ca

import (
	"crypto/x509"
	"io/ioutil"
	"testing"
)

func TestFetchAttributes(t *testing.T) {

	cert, err := loadECert()

	if err != nil {
		t.Fatalf("Error loading ECert: %v", err)
	}
	sock, acaP, err := GetTCAClient()
	if err != nil {
		t.Fatalf("Error executing test: %v", err)
	}
	defer sock.Close()
}

func loadECert() (*x509.Certificate, error) {
	ecertRaw, err := ioutil.ReadFile("./test_resources/ecert.dump")
	if err != nil {
		return nil, err
	}

	ecert, err := x509.ParseCertificate(ecertRaw)
	if err != nil {
		return nil, err
	}

	return ecert, nil
}
