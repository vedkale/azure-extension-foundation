// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

package msihttpclient

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"

	"github.com/Azure/azure-extension-foundation/errorhelper"
	"github.com/Azure/azure-extension-foundation/httputil"
	"github.com/Azure/azure-extension-foundation/metadata"
	"github.com/Azure/azure-extension-foundation/msi"
)

type msiHttpClient struct {
	httpClient    httpClientInterface
	retryBehavior httputil.RetryBehavior
	msi           *msi.Msi
	msiProvider   msi.MsiProvider
	metadata      *metadata.Metadata
}

var getHttpClientFunc = func() httpClientInterface {
	tlsConfig := &tls.Config{
		Renegotiation: tls.RenegotiateFreelyAsClient,
	}

	transport := &http.Transport{TLSClientConfig: tlsConfig}
	return &http.Client{Transport: transport}
}

type httpClientInterface interface {
	Do(req *http.Request) (*http.Response, error)
}

func NewMsiHttpClient(msiProvider msi.MsiProvider, mdata *metadata.Metadata, retryBehavior httputil.RetryBehavior) httputil.HttpClient {
	if retryBehavior == nil {
		panic("Retry policy must be specified")
	}
	if msiProvider == nil {
		panic("msiProvider must be specified")
	}
	httpClient := getHttpClientFunc()
	mhc := msiHttpClient{httpClient, retryBehavior, nil, msiProvider, mdata}
	mhc.refreshMsiAuthentication()
	return &mhc

}

func (client *msiHttpClient) Get(url string, headers map[string]string) (responseCode int, body []byte, err error) {
	code, _, body, err := client.issueRequest(httputil.OperationGet, url, headers, nil)
	return code, body, err
}

func (client *msiHttpClient) GetWithHeaders(url string, headers map[string]string) (responseCode int, respHeaders http.Header, body []byte, err error) {
	return client.issueRequest(httputil.OperationGet, url, headers, nil)
}

// Post issues a post request
func (client *msiHttpClient) Post(url string, headers map[string]string, payload []byte) (responseCode int, body []byte, err error) {
	code, _, body, err := client.issueRequest(httputil.OperationPost, url, headers, bytes.NewBuffer(payload))
	return code, body, err
}

// Put issues a put request
func (client *msiHttpClient) Put(url string, headers map[string]string, payload []byte) (responseCode int, body []byte, err error) {
	code, _, body, err := client.issueRequest(httputil.OperationPut, url, headers, bytes.NewBuffer(payload))
	return code, body, err
}

// Delete issues a delete request
func (client *msiHttpClient) Delete(url string, headers map[string]string, payload []byte) (responseCode int, body []byte, err error) {
	code, _, body, err := client.issueRequest(httputil.OperationDelete, url, headers, bytes.NewBuffer(payload))
	return code, body, err
}

func (client *msiHttpClient) addVmIdQueryParameterToUrl(u string) (string, error) {
	qParams, err := url.Parse(u)
	if err != nil {
		return "", err
	}
	qParams.RawQuery = fmt.Sprintf("%s&vmResourceId=%s", qParams.RawQuery, client.metadata.GetAzureResourceId())
	return qParams.String(), nil
}

func (client *msiHttpClient) refreshMsiAuthentication() error {

	if client.msi == nil {
		myMsi, err := client.msiProvider.GetMsi()
		if err != nil {
			return err
		}
		client.msi = &myMsi
	} else {
		tokenExpired, err := client.msi.IsMsiTokenExpired()
		if err != nil {
			return err
		}
		if tokenExpired {
			myMsi, err := client.msiProvider.GetMsi()
			if err != nil {
				return err
			}
			client.msi = &myMsi
		}
	}
	return nil
}

func (client *msiHttpClient) setMsiAuthenticationHeader(request *http.Request) {
	request.Header.Set("Authorization", fmt.Sprintf("Bearer %s", client.msi.AccessToken))
}

func (client *msiHttpClient) issueRequest(operation string, url string, headers map[string]string, payload *bytes.Buffer) (int, http.Header, []byte, error) {
	// add query parameter for vmId
	modifiedUrl, err := client.addVmIdQueryParameterToUrl(url)
	if err != nil {
		return -1, nil, nil, errorhelper.AddStackToError(err)
	}
	request, err := http.NewRequest(operation, modifiedUrl, nil)
	if payload != nil && payload.Len() != 0 {
		request, err = http.NewRequest(operation, modifiedUrl, payload)
	}

	// Initialize and refresh msi as required
	err = client.refreshMsiAuthentication()
	if err != nil {
		return -1, nil, nil, errorhelper.AddStackToError(err)
	}
	// Add authorization if required
	client.setMsiAuthenticationHeader(request)

	// add headers
	for key, value := range headers {
		request.Header.Set(key, value)
	}

	res, err := client.httpClient.Do(request)
	if err == nil && httputil.IsSuccessStatusCode(res.StatusCode) {
		// no need to retry
	} else if err == nil && res != nil {
		for i := 1; client.retryBehavior(res.StatusCode, i); i++ {
			// Initialize as refresh msi as required
			err = client.refreshMsiAuthentication()
			if err != nil {
				return -1, nil, nil, errorhelper.AddStackToError(err)
			}
			// Add authorization if required
			client.setMsiAuthenticationHeader(request)
			res, err = client.httpClient.Do(request)
			if err != nil {
				break
			}
		}
	}

	if err != nil {
		return -1, nil, nil, errorhelper.AddStackToError(err)
	}

	body, err := ioutil.ReadAll(res.Body)
	res.Body.Close()
	code := res.StatusCode
	if err != nil {
		return -1, nil, nil, errorhelper.AddStackToError(err)
	}

	return code, res.Header, body, nil
}
