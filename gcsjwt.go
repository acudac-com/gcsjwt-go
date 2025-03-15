package gcsjwt

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"sync"
	"time"

	"cloud.google.com/go/storage"
	"github.com/golang-jwt/jwt"
	"google.golang.org/api/option"
)

var gcsClient *storage.Client
var gcsJwt *GcsJwt

// Provides functions to create and validate jwts.
// Uses Google Cloud Storage to store the 4096 bit private RSA keys.
type GcsJwt struct {
	bucketHandle *storage.BucketHandle
	cachedKeys   *sync.Map
}

// PublicKey represents a public key
type PublicKey struct {
	// Key ID
	Kid string
	// PEM encoded public key
	Key string
}

func (p *PublicKey) String() string {
	return fmt.Sprintf("Kid: %s, Key: %s", p.Kid, p.Key)
}

// Returns a new GcsJwt to create and validate jwt tokens.
func New(bucket string, opts ...option.ClientOption) (*GcsJwt, error) {
	// Create a new Storage client if one does not exist.
	if gcsClient == nil {
		ctx := context.Background()
		var err error
		if gcsClient, err = storage.NewClient(ctx, opts...); err != nil {
			return nil, fmt.Errorf("creating GCS client: %w", err)
		}
	}

	// Set the Storage client.
	return &GcsJwt{
		bucketHandle: gcsClient.Bucket(bucket),
		cachedKeys:   &sync.Map{},
	}, nil
}

// Equivalent to New, but does not return the GcsJwt instance, but rather keeps it in local storage.
// After initialisation, SignedJwt, PublicKeys and Validate can be used.
func Init(bucket string, opts ...option.ClientOption) error {
	var err error
	if gcsJwt, err = New(bucket, opts...); err != nil {
		return err
	}
	return nil
}

// Returns a signed jwt token with the provided claims.
// It is higly recommended to use common claims like sub, email, iss, aud and exp.
func SignedJwt(ctx context.Context, claims jwt.MapClaims) (string, error) {
	if gcsJwt == nil {
		return "", fmt.Errorf("local gcsJwt instance not yet initialised via Init")
	}
	return gcsJwt.SignedJwt(ctx, claims)
}

// Returns the two public keys currently in rotation.
func PublicKeys(ctx context.Context) ([]*PublicKey, error) {
	if gcsJwt == nil {
		return nil, fmt.Errorf("local gcsJwt instance not yet initialised via Init")
	}
	return gcsJwt.PublicKeys(ctx)
}

// Returns the jwt claims if validation succeeds.
// Fails if the signedJwt has the incorrect signature or is expired.
func Validate(ctx context.Context, signedJwt string) (jwt.MapClaims, error) {
	if gcsJwt == nil {
		return nil, fmt.Errorf("local gcsJwt instance not yet initialised via Init")
	}
	return gcsJwt.Validate(ctx, signedJwt)
}

// Returns a signed jwt token with the provided claims.
// It is higly recommended to use common claims like sub, email, iss, aud and exp.
func (g *GcsJwt) SignedJwt(ctx context.Context, claims jwt.MapClaims) (string, error) {
	// get the private key
	keyId := time.Now().UTC().Format("2006-01-02")
	keys, err := g.rsaKeys(ctx, []string{keyId})
	if err != nil {
		return "", err
	}

	// create new unsigned jwt token with provided claims
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = keyId

	// Sign the token with the private key
	signedJwt, err := token.SignedString(keys[0])
	if err != nil {
		return "", fmt.Errorf("failed to sign token: %w", err)
	}

	return signedJwt, nil
}

// Returns the two public keys currently in rotation.
func (g *GcsJwt) PublicKeys(ctx context.Context) ([]*PublicKey, error) {
	// determine which key ids to get based on today and yesterday
	today := time.Now().UTC()
	today = time.Date(today.Year(), today.Month(), today.Day(), 0, 0, 0, 0, time.UTC)
	yesterday := today.AddDate(0, 0, -1)
	todayKeyId := today.Format("2006-01-02")
	yesterdayKeyId := yesterday.Format("2006-01-02")
	keyIds := []string{todayKeyId, yesterdayKeyId}

	// get the rsa private keys
	keys, err := g.rsaKeys(ctx, keyIds)
	if err != nil {
		return nil, err
	}

	// convert to public keys
	publicKeys := []*PublicKey{}
	for i, key := range keys {
		publicKeyPem := &pem.Block{
			Type:  "RSA PUBLIC KEY",
			Bytes: x509.MarshalPKCS1PublicKey(&key.PublicKey),
		}
		PublicKey := &PublicKey{
			Kid: keyIds[i],
			Key: string(pem.EncodeToMemory(publicKeyPem)),
		}
		publicKeys = append(publicKeys, PublicKey)
	}
	return publicKeys, nil
}

// Returns the jwt claims if validation succeeds.
// Fails if the signedJwt has the incorrect signature or is expired.
func (g *GcsJwt) Validate(ctx context.Context, signedJwt string) (jwt.MapClaims, error) {
	claims := jwt.MapClaims{}
	_, err := jwt.ParseWithClaims(signedJwt, claims, func(token *jwt.Token) (interface{}, error) {
		// get kid from headers
		kid, ok := token.Header["kid"].(string)
		if !ok {
			return nil, fmt.Errorf("kid not found")
		}

		// fail if kid not today or yesterday's key
		todayUtc := time.Now().UTC()
		todayKey := todayUtc.Format("2006-01-02")
		yesterdayKey := todayUtc.AddDate(0, 0, -1).Format("2006-01-02")
		if kid != todayKey && kid != yesterdayKey {
			return nil, fmt.Errorf("invalid key id")
		}

		// find key for validation
		key, err := g.rsaKeys(ctx, []string{kid})
		if err != nil {
			return nil, fmt.Errorf("failed to get public key: %w", err)
		}
		return &key[0].PublicKey, nil
	})
	if err != nil {
		return nil, err
	}
	return claims, nil
}

// Returns the bytes in the provided Google Cloud Storage object.
func (g *GcsJwt) readObject(ctx context.Context, object string) ([]byte, error) {
	// Create reader
	reader, err := g.bucketHandle.Object(object).NewReader(ctx)
	if err != nil {
		return nil, err
	}
	defer reader.Close()

	// Read and return all bytes
	return io.ReadAll(reader)
}

// Writes the bytes to the object if the object does not already exists.
// Concurrency proof.
func (g *GcsJwt) uploadObjectIfMissing(ctx context.Context, object string, bytes []byte) error {
	// Create object handle
	objHandle := g.bucketHandle.Object(object).If(storage.Conditions{DoesNotExist: true})

	// Create writer
	wr := objHandle.NewWriter(ctx)
	_, err := wr.Write(bytes)
	if err != nil {
		return err
	}

	// try to write
	err = wr.Close()
	if err != nil {
		return err
	}
	return nil
}

// Returns the rsa private keys for the given key ids. If the key does not exist, it will be created.
func (g *GcsJwt) rsaKeys(ctx context.Context, keyIds []string) ([]*rsa.PrivateKey, error) {
	keys := []*rsa.PrivateKey{}
	for _, keyId := range keyIds {
		// return from cache if exists
		if key, ok := g.cachedKeys.Load(keyId); ok {
			keys = append(keys, key.(*rsa.PrivateKey))
			continue
		}

		// read from storage
		keyBytes, err := g.readObject(ctx, keyId)
		if err == nil {
			block, _ := pem.Decode(keyBytes)
			key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("failed to parse private key: %w", err)
			}
			g.cachedKeys.Store(keyId, key)
			keys = append(keys, key)
			continue
		} else {
			// create new rsa private key
			privKey, err := rsa.GenerateKey(rand.Reader, 4096)
			if err != nil {
				return nil, fmt.Errorf("failed to generate private key: %w", err)
			}

			// determine PEM encoded rsa private key
			keyBytes = pem.EncodeToMemory(&pem.Block{
				Type:  "RSA PRIVATE KEY",
				Bytes: x509.MarshalPKCS1PrivateKey(privKey),
			})

			// upload if does not yet exist
			err = g.uploadObjectIfMissing(ctx, keyId, keyBytes)
			if err != nil {
				// if failed to write, try to read again
				keyBytes, err = g.readObject(ctx, keyId)
				if err != nil {
					return nil, fmt.Errorf("failed to read private key: %w", err)
				}

				// parse the key
				block, _ := pem.Decode(keyBytes)
				privKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
				if err != nil {
					return nil, fmt.Errorf("failed to parse private key: %w", err)
				}
			}

			// add to cache and list of keys
			g.cachedKeys.Store(keyId, privKey)
			keys = append(keys, privKey)
			continue
		}
	}
	return keys, nil
}
