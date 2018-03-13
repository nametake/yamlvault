package yamlvault

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"io/ioutil"

	"github.com/go-yaml/yaml"
	"github.com/pkg/errors"
	"golang.org/x/oauth2/google"
	cloudkms "google.golang.org/api/cloudkms/v1"
)

type KMS struct {
	Service    *cloudkms.Service
	ProjectID  string
	LocationID string
	KeyRingID  string
	KeyName    string
}

func NewKMS(ctx context.Context, project, location, keyring, keyname string) (*KMS, error) {
	client, err := google.DefaultClient(ctx, cloudkms.CloudPlatformScope)
	if err != nil {
		return nil, errors.Wrap(err, "failed create google.DefaultClient: ")
	}

	kmsService, err := cloudkms.New(client)
	if err != nil {
		return nil, errors.Wrap(err, "failed cloudkms.New: ")
	}

	return &KMS{
		Service:    kmsService,
		ProjectID:  project,
		LocationID: location,
		KeyRingID:  keyring,
		KeyName:    keyname,
	}, nil
}

func (k *KMS) Name() string {
	return fmt.Sprintf("projects/%s/locations/%s/keyRings/%s/cryptoKeys/%s", k.ProjectID, k.LocationID, k.KeyRingID, k.KeyName)
}

func (k *KMS) Encrypt(r io.Reader) (io.Writer, error) {
	m, err := unmarshal(r)
	if err != nil {
		return nil, err
	}

	result := make(map[interface{}]interface{})
	for key, value := range m {
		resp, err := k.Service.Projects.Locations.KeyRings.CryptoKeys.Encrypt(k.Name(), &cloudkms.EncryptRequest{
			Plaintext: base64.StdEncoding.EncodeToString([]byte(value.(string))),
		}).Do()
		if err != nil {
			return nil, errors.Wrapf(err, "encrypt: failed to encrypt. CryptoKey=%s", k.Name())
		}
		result[key] = resp.Ciphertext
	}

	return marshal(result)
}

func (k *KMS) Decrypt(r io.Reader) (io.Writer, error) {
	m, err := unmarshal(r)
	if err != nil {
		return nil, err
	}

	result := make(map[interface{}]interface{})
	for key, value := range m {
		resp, err := k.Service.Projects.Locations.KeyRings.CryptoKeys.Decrypt(k.Name(), &cloudkms.DecryptRequest{
			Ciphertext: value.(string),
		}).Do()
		if err != nil {
			return nil, errors.Wrapf(err, "encrypt: failed to encrypt. CryptoKey=%s", k.Name())
		}
		result[key] = resp.Plaintext
	}

	return marshal(result)
}

func unmarshal(r io.Reader) (map[interface{}]interface{}, error) {
	m := make(map[interface{}]interface{})

	b, err := ioutil.ReadAll(r)
	if err != nil {
		return nil, err
	}

	if err := yaml.Unmarshal(b, &m); err != nil {
		return nil, err
	}

	return m, nil
}

func marshal(m map[interface{}]interface{}) (io.Writer, error) {
	b, err := yaml.Marshal(m)
	if err != nil {
		return nil, err
	}

	return bytes.NewBuffer(b), nil
}
