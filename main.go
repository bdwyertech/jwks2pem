package main

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"os"

	"github.com/lestrrat-go/jwx/jwk"
)

func main() {
	if len(os.Args) < 2 {
		log.Fatal("Must supply JWKS url as argument!")
	}
	url := os.Args[1]
	set, err := jwk.Fetch(context.Background(), url)
	if err != nil {
		log.Printf("failed to parse JWK: %s", err)
		return
	}

	var kid *string

	if len(os.Args) >= 3 {
		kid = &os.Args[2]
	}

	for it := set.Iterate(context.Background()); it.Next(context.Background()); {
		pair := it.Pair()
		key := pair.Value.(jwk.Key)
		key, err := jwk.PublicKeyOf(key)
		if err != nil {
			log.Fatal(err)
		}

		if kid != nil && key.KeyID() != *kid {
			continue
		}

		var rawkey interface{}
		if err := key.Raw(&rawkey); err != nil {
			log.Printf("failed to create public key: %s", err)
			return
		}

		publicDer, err := x509.MarshalPKIXPublicKey(rawkey)
		if err != nil {
			log.Fatal(err)
		}

		publicKeyBlock := pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: publicDer,
		}
		publicKeyPem := pem.EncodeToMemory(&publicKeyBlock)

		fmt.Println(string(publicKeyPem))

		if kid != nil && key.KeyID() == *kid {
			break
		}
	}
}
