package protocol

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/overte-org/overte-ice-server/internal/qtstream"
	"github.com/overte-org/overte-ice-server/internal/registry"
)

type Socket struct {
	Display string
	Raw     []byte
}
type Heartbeat struct {
	DomainID      string
	Public, Local Socket
	Signed        []byte
	Signature     []byte
}
type Query struct {
	SenderID      string
	Public, Local Socket
	TargetID      string
}
type Peer struct {
	ID            string
	Public, Local Socket
	Observed      string
	LastSeen      time.Time
}

func ParseHeartbeat(payload []byte) (Heartbeat, error) {
	r := qtstream.Reader{B: payload}
	id, uuidBytes, e := r.UUID()
	if e != nil {
		return Heartbeat{}, e
	}
	if !validUUIDBytes(uuidBytes) {
		return Heartbeat{}, errors.New("invalid domain UUID in ICE heartbeat")
	}
	pub, praw, e := r.Socket()
	if e != nil {
		return Heartbeat{}, e
	}
	local, lraw, e := r.Socket()
	if e != nil {
		return Heartbeat{}, e
	}
	signedEnd := r.Off
	sig, e := r.QByteArray()
	if e != nil {
		return Heartbeat{}, e
	}
	if r.Off != len(payload) {
		return Heartbeat{}, errors.New("unexpected trailing bytes in heartbeat")
	}
	return Heartbeat{DomainID: id, Public: Socket{pub, praw}, Local: Socket{local, lraw}, Signed: append([]byte(nil), payload[:signedEnd]...), Signature: sig}, nil
}
func ParseQuery(payload []byte) (Query, error) {
	r := qtstream.Reader{B: payload}
	id, senderUUID, e := r.UUID()
	if e != nil {
		return Query{}, e
	}
	if !validUUIDBytes(senderUUID) {
		return Query{}, errors.New("invalid sender UUID in ICE query")
	}
	pub, praw, e := r.Socket()
	if e != nil {
		return Query{}, e
	}
	local, lraw, e := r.Socket()
	if e != nil {
		return Query{}, e
	}
	target, targetUUID, e := r.UUID()
	if e != nil {
		return Query{}, e
	}
	if !validUUIDBytes(targetUUID) {
		return Query{}, errors.New("invalid target UUID in ICE query")
	}
	if r.Off != len(payload) {
		return Query{}, errors.New("unexpected trailing bytes in ICE query")
	}
	return Query{SenderID: id, Public: Socket{pub, praw}, Local: Socket{local, lraw}, TargetID: target}, nil
}
// validUUIDBytes checks the UUID version and RFC variant used by Overte's
// generated peer identifiers. It accepts versions 1 through 8 so newer UUID
// versions remain valid without accepting nil or malformed identifiers.
func validUUIDBytes(id []byte) bool {
	if len(id) != 16 {
		return false
	}
	version := id[6] >> 4
	variant := id[8] >> 6
	return version >= 1 && version <= 8 && variant == 2
}

func PeerPayload(p Peer) ([]byte, error) {
	id, e := qtstream.UUIDBytes(p.ID)
	if e != nil {
		return nil, e
	}
	if len(p.Public.Raw) == 0 || len(p.Local.Raw) == 0 {
		return nil, errors.New("peer socket serialization missing")
	}
	out := make([]byte, 0, 16+len(p.Public.Raw)+len(p.Local.Raw))
	out = append(out, id...)
	out = append(out, p.Public.Raw...)
	out = append(out, p.Local.Raw...)
	return out, nil
}

type publicKeyResponse struct {
	Status string `json:"status"`
	Data   struct {
		PublicKey string `json:"public_key"`
	} `json:"data"`
}

const (
	maxPublicKeyResponseSize = 64 << 10
	overteRSAModulusBits      = 2048
	overteRSAExponent         = 65537
)

func FetchPublicKey(client *http.Client, dir registry.Directory, domainID string) (*rsa.PublicKey, error) {
	base, e := url.Parse(dir.BaseURL)
	if e != nil {
		return nil, e
	}
	base.Path = strings.TrimRight(base.Path, "/") + "/api/v1/domains/" + domainID + "/public_key"
	req, e := http.NewRequest(http.MethodGet, base.String(), nil)
	if e != nil {
		return nil, e
	}
	resp, e := client.Do(req)
	if e != nil {
		return nil, e
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("directory returned HTTP %d", resp.StatusCode)
	}
	body, e := io.ReadAll(io.LimitReader(resp.Body, maxPublicKeyResponseSize+1))
	if e != nil {
		return nil, e
	}
	if len(body) > maxPublicKeyResponseSize {
		return nil, fmt.Errorf("directory public-key response exceeds %d bytes", maxPublicKeyResponseSize)
	}
	var response publicKeyResponse
	if e = json.Unmarshal(body, &response); e != nil {
		return nil, e
	}
	if response.Status != "success" || response.Data.PublicKey == "" {
		return nil, errors.New("directory response did not contain data.public_key")
	}
	der, e := base64.StdEncoding.DecodeString(response.Data.PublicKey)
	if e != nil {
		return nil, e
	}
	var rsaKey *rsa.PublicKey
	if key, parseErr := x509.ParsePKIXPublicKey(der); parseErr == nil {
		rsaKey, _ = key.(*rsa.PublicKey)
	}
	if rsaKey == nil {
		rsaKey, _ = x509.ParsePKCS1PublicKey(der)
	}
	if rsaKey == nil {
		return nil, errors.New("public_key is not a supported RSA DER public key")
	}
	if rsaKey.N == nil || rsaKey.N.BitLen() != overteRSAModulusBits {
		return nil, fmt.Errorf("public_key must use a %d-bit RSA modulus", overteRSAModulusBits)
	}
	if rsaKey.E != overteRSAExponent {
		return nil, fmt.Errorf("public_key must use RSA exponent %d", overteRSAExponent)
	}
	return rsaKey, nil
}
func VerifyHeartbeat(key *rsa.PublicKey, signed, signature []byte) error {
	if key == nil {
		return errors.New("public key unavailable")
	}
	digest := sha256.Sum256(signed)
	return rsa.VerifyPKCS1v15(key, crypto.SHA256, digest[:], signature)
}
