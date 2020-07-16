package main

import (
	//"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"time"

	jose "gopkg.in/square/go-jose.v2"
	//"github.com/square/go-jose"
	"github.com/square/go-jose/jwt"
)

func main() {
	/*/ Generate a public/private key pair to use for this example.
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	*/
	pemData, err := ioutil.ReadFile("secret.pem")
	if err != nil {
		panic(err)
	}
	var privateKey *rsa.PrivateKey
	var block *pem.Block
	for len(pemData) > 0 {
		block, pemData = pem.Decode(pemData)
		switch block.Type {
		case "CERTIFICATE":
			// the private key has the public key inside
		case "RSA PRIVATE KEY":
			privateKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
			if err != nil {
				panic(err)
			}
		}
	}
	// Instantiate an encrypter using RSA-OAEP with AES128-GCM. An error would
	// indicate that the selected algorithm(s) are not currently supported.
	publicKey := &privateKey.PublicKey

	/*
		encrypter, err := jose.NewEncrypter(jose.A128GCM, jose.Recipient{Algorithm: jose.RSA_OAEP, Key: publicKey}, nil)
		if err != nil {
			panic(err)
		}

		// Encrypt a sample plaintext. Calling the encrypter returns an encrypted
		// JWE object, which can then be serialized for output afterwards. An error
		// would indicate a problem in an underlying cryptographic primitive.
		var plaintext = []byte("Lorem ipsum dolor sit amet")
		object, err := encrypter.Encrypt(plaintext)
		if err != nil {
			panic(err)
		}

		// Serialize the encrypted object using the full serialization format.
		// Alternatively you can also use the compact format here by calling
		// object.CompactSerialize() instead.
		serialized := object.FullSerialize()

		// Parse the serialized, encrypted JWE object. An error would indicate that
		// the given input did not represent a valid message.
		object, err = jose.ParseEncrypted(serialized)
		if err != nil {
			panic(err)
		}

		// Now we can decrypt and get back our original plaintext. An error here
		// would indicate the the message failed to decrypt, e.g. because the auth
		// tag was broken or the message was tampered with.
		decrypted, err := object.Decrypt(privateKey)
		if err != nil {
			panic(err)
		}

		fmt.Println(string(decrypted))
	*/

	sig, err := jose.NewSigner(jose.SigningKey{
		Algorithm: jose.RS256,
		Key:       privateKey,
	}, (&jose.SignerOptions{}).WithType("JWT"))
	if err != nil {
		panic(err)
	}
	enc, err := jose.NewEncrypter(
		jose.A128GCM,
		jose.Recipient{
			Algorithm: jose.RSA_OAEP,
			Key:       publicKey,
		},
		(&jose.EncrypterOptions{}).WithContentType("JWT").WithType("JWT"))
	if err != nil {
		panic(err)
	}

	c := map[string]interface{}{
		"sub":        "subject",
		"iss":        "issuer",
		"iat":        time.Now().Unix(),
		"exp":        time.Now().Add(30 * 24 * time.Hour).Unix(),
		"source_ip":  "stuff",
		"source_dns": "stuff",
		"user_agent": "stuff",
	}
	raw, err := jwt.SignedAndEncrypted(sig, enc).Claims(c).CompactSerialize()
	if err != nil {
		panic(err)
	}

	fmt.Println(raw)
	fmt.Printf("LEN: %d\n", len(raw))
	tok, err := jwt.ParseSignedAndEncrypted(raw)
	if err != nil {
		panic(err)
	}
	nested, err := tok.Decrypt(privateKey)
	if err != nil {
		panic(err)
	}
	out := make(map[string]interface{})
	if err := nested.Claims(&privateKey.PublicKey, &out); err != nil {
		panic(err)
	}

	for k, v := range out {
		switch val := v.(type) {
		case string:
			fmt.Printf("%s: %s\n", k, val)
		case float64:
			fmt.Printf("%s: %s\n", k, time.Unix(int64(val), 0).Format(time.RFC3339Nano))
		}
	}
}
