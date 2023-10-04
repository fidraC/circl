package ntrulpr653_test

import (
	"log"
	"testing"

	"github.com/cloudflare/circl/kem/ntruprime/ntrulpr653"
	"github.com/stretchr/testify/assert"
)

func TestEncapDecap(t *testing.T) {
	scheme := ntrulpr653.Scheme()
	var (
		pk *ntrulpr653.PublicKey
		sk *ntrulpr653.PrivateKey
	)
	pki, ski, err := scheme.GenerateKeyPair()
	if err != nil {
		t.Error(err)
	}
	pk = pki.(*ntrulpr653.PublicKey)
	sk = ski.(*ntrulpr653.PrivateKey)
	cipherText := make([]byte, ntrulpr653.CiphertextSize)
	sharedKey := make([]byte, ntrulpr653.SharedKeySize)
	pk.EncapsulateTo(cipherText, sharedKey, nil)
	newSharedKey := make([]byte, ntrulpr653.SharedKeySize)
	sk.DecapsulateTo(newSharedKey, cipherText)
	if !assert.Equal(t, sharedKey, newSharedKey) {
		t.Error("failed to retrieve shared key")
	}
	log.Println(len(sharedKey))
}
