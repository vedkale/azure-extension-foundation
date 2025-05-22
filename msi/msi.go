// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

package msi

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"time"

	"github.com/Azure/azure-extension-foundation/errorhelper"
	"github.com/Azure/azure-extension-foundation/httputil"
)

const (
	metadataIdentityURL = "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01"

	clientIdQueryParam = "client_id"
	objectIdQueryParam = "object_id"
	resourceQueryParam = "resource"

	armResourceUri = "https://management.core.windows.net/"

	identityEnvVar = "IDENTITY_ENDPOINT"
)

type Msi struct {
	AccessToken  string `json:"access_token"`
	ClientID     string `json:"client_id"`
	ExpiresIn    string `json:"expires_in"`
	ExpiresOn    string `json:"expires_on"` // expressed in seconds from epoch
	ExtExpiresIn string `json:"ext_expires_in"`
	NotBefore    string `json:"not_before"`
	Resource     string `json:"resource"`
	TokenType    string `json:"token_type"`
}

type MsiProvider interface {
	GetMsi() (Msi, error)
	GetMsiForResource(targetResource string) (Msi, error)
	GetMsiUsingClientId(clientId string, targetResource string) (Msi, error)
	GetMsiUsingObjectId(objectId string, targetResource string) (Msi, error)
}

type provider struct {
	httpClient httputil.HttpClient
}

func NewMsiProvider(client httputil.HttpClient) provider {
	return provider{httpClient: client}
}

func (p *provider) getMsiHelper(queryParams map[string]string) (*Msi, error) {
	var msi = Msi{}
	requestUrl, err := url.Parse(GetMetadataIdentityURL())
	if err != nil {
		return &msi, err
	}
	urlQuery := requestUrl.Query()
	for key, value := range queryParams {
		urlQuery.Add(key, value)
	}
	requestUrl.RawQuery = urlQuery.Encode()

	code, respHeaders, body, err := p.httpClient.GetWithHeaders(requestUrl.String(), map[string]string{"Metadata": "true"})
	if err != nil {
		return &msi, err
	}

	// Arc uses a challenge response mechanism to get the token
	// If the response code is 401, Arc will have a header Www-Authenticate: Basic realm=<location of the token>
	if GetMetadataIdentityURL() != metadataIdentityURL && code == 401 {
		wwwAuthenticateHeader, exists := respHeaders["Www-Authenticate"]
		if !exists || len(wwwAuthenticateHeader) == 0 {
			return &msi, errorhelper.AddStackToError(fmt.Errorf("unable to get msi, metadata service response code %v: Www-Authenticate header missing or empty", code))
		}
		tokenLocation := wwwAuthenticateHeader[0]
		if len(tokenLocation) == 0 {
			return &msi, errorhelper.AddStackToError(fmt.Errorf("unable to get msi, metadata service response code %v: token location is empty", code))
		}

		tokenLocation = tokenLocation[len("Basic realm="):]
		token, err := os.ReadFile(tokenLocation)
		if err != nil {
			return &msi, errorhelper.AddStackToError(fmt.Errorf("unable to read arc token file %s", tokenLocation))
		}

		code, body, err = p.httpClient.Get(requestUrl.String(), map[string]string{"Metadata": "true", "Authorization": "Basic " + string(token)})
		if err != nil {
			return &msi, err
		}
	}

	if code != 200 {
		return &msi, errorhelper.AddStackToError(fmt.Errorf("unable to get msi, metadata service response code %v", code))
	}

	err = json.Unmarshal(body, &msi)
	if err != nil {
		return &msi, errorhelper.AddStackToError(fmt.Errorf("unable to deserialize metadata service response"))
	}
	return &msi, nil
}

func (p *provider) GetMsi() (Msi, error) {
	msi, err := p.getMsiHelper(map[string]string{resourceQueryParam: armResourceUri})
	return *msi, err
}

func (p *provider) GetMsiForResource(targetResource string) (Msi, error) {
	msi, err := p.getMsiHelper(map[string]string{resourceQueryParam: targetResource})
	return *msi, err
}

func (p *provider) GetMsiUsingClientId(clientId string, targetResource string) (Msi, error) {
	msi, err := p.getMsiHelper(map[string]string{clientIdQueryParam: clientId, resourceQueryParam: targetResource})
	return *msi, err
}

func (p *provider) GetMsiUsingObjectId(objectId string, targetResource string) (Msi, error) {
	msi, err := p.getMsiHelper(map[string]string{objectIdQueryParam: objectId, resourceQueryParam: targetResource})
	return *msi, err
}

// check expiry of MSI token based on time
func (msi *Msi) IsMsiTokenExpired() (bool, error) {
	expiryTime, err := msi.GetExpiryTime()
	if err != nil {
		return false, err
	}

	// Consider token expired 2 minutes before expiry time
	expiryTime = expiryTime.Add(-2 * time.Minute)

	if time.Now().After(expiryTime) {
		return true, nil
	} else {
		return false, nil
	}
}

func (msi *Msi) GetExpiryTime() (time.Time, error) {
	expiryTimeInSeconds, err := strconv.ParseInt(msi.ExpiresOn, 10, 64)
	if err != nil {
		return time.Unix(0, 0), err
	}
	expiryTime := time.Unix(expiryTimeInSeconds, 0)
	return expiryTime, nil
}

func (msi *Msi) GetJson() (string, error) {
	jsonBytes, err := json.Marshal(msi)
	return string(jsonBytes[:]), err
}

func GetMetadataIdentityURL() string {
	envMetadataIdentityURL := os.Getenv(identityEnvVar)
	if envMetadataIdentityURL != "" {
		// the identity endpoint doesn't contain the api-version query parameter
		return envMetadataIdentityURL + "?api-version=2021-02-01"
	}
	return metadataIdentityURL
}
