package pubtkt

import (
	"crypto/dsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"golang.org/x/crypto/ssh"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type AuthPubTkt interface {
	// Verify ticket and pre-check from a request
	VerifyFromRequest(*http.Request) (*Ticket, error)
	// Transform a request to a ticket (if found)
	RequestToTicket(*http.Request) (*Ticket, error)
	// Transform an encoded ticket or plain ticket as a ticket strcture
	RawToTicket(ticketStr string) (*Ticket, error)
	// Verify a ticket with signature, expiration, token (if set) and ip (against the provided ip and if TKTCheckIpEnabled option is true)
	VerifyTicket(ticket *Ticket, clientIp string) error
	// Sign a ticket
	GenerateSignature(ticket *Ticket)(signature string, err error)
}
type AuthPubTktImpl struct {
	options AuthPubTktOptions
	openSSL *OpenSSL
	rsaPrivKey *rsa.PrivateKey
	dsaPrivKey *dsa.PrivateKey
}

var TimeNowFunc = func() time.Time {
	return time.Now()
}


func NewAuthPubTkt(options AuthPubTktOptions) (AuthPubTkt, error) {
	if options.TKTAuthPublicKey == "" {
		return nil, fmt.Errorf("TKTAuthPublicKey must be set")
	}
	if options.TKTAuthCookieName == "" {
		options.TKTAuthCookieName = "auth_pubtkt"
	}
	if options.TKTAuthHeader == nil || len(options.TKTAuthHeader) == 0 {
		options.TKTAuthHeader = []string{"cookie"}
	}
	if options.TKTAuthDigest == "" {
		pubkeyType, err := options.DetectPubkeyType()
		if err != nil {
			return nil, err
		}
		// those are mod_auth_pubtkt defaults
		switch pubkeyType {
		case "rsa":
			options.TKTAuthDigest = "sha1"
		case "dsa":
			options.TKTAuthDigest = "dss1"
		default:
			return nil, fmt.Errorf("pubkey type %s not supported", pubkeyType)
		}
	} else {
		options.TKTAuthDigest = strings.ToLower(options.TKTAuthDigest)
	}
	return &AuthPubTktImpl{options: options, openSSL: NewOpenSSL()}, nil
}
func (a AuthPubTktImpl) VerifyFromRequest(req *http.Request) (*Ticket, error) {
	if req.TLS == nil && a.options.TKTAuthRequireSSL {
		return nil, NewErrNoSSl()
	}
	ip := strings.Split(req.RemoteAddr, ":")[0]
	if a.options.TKTCheckXForwardedIp {
		xffClient := strings.TrimSpace(strings.Split(req.Header.Get("X-Forwarded-For"), ",")[0])
		ip = strings.Split(xffClient, ":")[0]
	}
	ticket, err := a.RequestToTicket(req)
	if err != nil {
		return nil, err
	}
	err = a.VerifyTicket(ticket, ip)
	if err != nil {
		return nil, err
	}
	return ticket, nil
}
func (a AuthPubTktImpl) RequestToTicket(req *http.Request) (*Ticket, error) {
	var content string
	for _, header := range a.options.TKTAuthHeader {
		header = strings.ToLower(header)
		if header != "cookie" {
			content = req.Header.Get(header)
			if content == "" {
				continue
			}
		}
		cookie, err := req.Cookie(a.options.TKTAuthCookieName)
		if err != nil {
			continue
		}
		content = cookie.Value
		break
	}
	if content == "" {
		return nil, NewErrNoTicket()
	}
	content, err := url.QueryUnescape(content)
	if err != nil {
		return nil, err
	}
	return a.RawToTicket(content)
}
func (a AuthPubTktImpl) RawToTicket(ticketStr string) (*Ticket, error) {
	var err error
	if a.options.TKTCypherTicketsWithPasswd != "" {
		ticketStr, err = a.decrypt(ticketStr)
		if err != nil {
			return nil, err
		}
	}
	return ParseTicket(ticketStr)
}

func (a AuthPubTktImpl) VerifyTicket(ticket *Ticket, clientIp string) error {
	err := a.verifySignature(ticket)
	if err != nil {
		return err
	}
	err = a.verifyToken(ticket)
	if err != nil {
		return err
	}
	err = a.verifyIp(ticket, clientIp)
	if err != nil {
		return err
	}
	err = a.verifyExpiration(ticket)
	if err != nil {
		return err
	}
	return nil
}
func (a AuthPubTktImpl) verifyIp(ticket *Ticket, ip string) error {
	if !a.options.TKTCheckIpEnabled || ticket.Cip == "" {
		return nil
	}
	if ticket.Cip != ip {
		return NewErrWrongIp()
	}
	return nil
}
func (a AuthPubTktImpl) verifyToken(ticket *Ticket) error {
	if a.options.TKTAuthToken == nil || len(a.options.TKTAuthToken) == 0 {
		return nil
	}
	tokTicketMap := make(map[string]bool)
	for _, tok := range ticket.Tokens {
		tokTicketMap[tok] = true
	}
	for _, tok := range a.options.TKTAuthToken {
		if _, ok := tokTicketMap[tok]; ok {
			return nil
		}
	}
	return NewErrNoValidToken()
}
func (a AuthPubTktImpl) verifyExpiration(ticket *Ticket) error {
	if !ticket.Validuntil.IsZero() && TimeNowFunc().After(ticket.Validuntil) {
		return NewErrValidationExpired()
	}
	if !ticket.Graceperiod.IsZero() && TimeNowFunc().After(ticket.Graceperiod) {
		return NewErrGracePeriodExpired()
	}
	return nil
}
func (a AuthPubTktImpl) verifySignature(ticket *Ticket) error {
	switch a.options.TKTAuthDigest {
	// no digest defined and it can't be guessed for pubkey, try both
	case "":
		err := a.verifyDsaSignature(ticket)
		if err == nil {
			return nil
		}
		return a.verifyRsaSignature(ticket)
	case "dss1":
		return a.verifyDsaSignature(ticket)
	default:
		return a.verifyRsaSignature(ticket)
	}
}
func (a AuthPubTktImpl) verifyDsaSignature(ticket *Ticket) error {
	block, _ := pem.Decode([]byte(a.options.TKTAuthPublicKey))
	if block == nil {
		return fmt.Errorf("no TKTAuthPublicKey found")
	}
	cert, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return fmt.Errorf("Error when parse public key: %s", err.Error())
	}
	pub, isDsa := cert.(*dsa.PublicKey)
	if !isDsa {
		return fmt.Errorf("not a DSA Key")
	}

	certif := x509.Certificate{
		PublicKey: pub,
	}
	signature, err := base64.StdEncoding.DecodeString(ticket.Sig)
	if err != nil {
		return NewErrSigNotValid(err)
	}
	err = certif.CheckSignature(x509.DSAWithSHA1, []byte(ticket.DataString()), signature)
	if err != nil {
		return NewErrSigNotValid(err)
	}
	return nil
}
func (a AuthPubTktImpl) verifyRsaSignature(ticket *Ticket) error {
	block, _ := pem.Decode([]byte(a.options.TKTAuthPublicKey))
	if block == nil {
		return fmt.Errorf("no TKTAuthPublicKey found")
	}
	cert, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return fmt.Errorf("Error when parse public key: %s", err.Error())
	}
	pub, isRsa := cert.(*rsa.PublicKey)
	if !isRsa {
		return fmt.Errorf("not a RSA Key")
	}
	ds, _ := base64.StdEncoding.DecodeString(ticket.Sig)
	authDigest := a.options.TKTAuthDigest
	hash, cryptoHash, err := FindHash(authDigest)
	if err != nil {
		return fmt.Errorf("Error when finding hash: %s", err.Error())
	}
	hash.Write([]byte(ticket.DataString()))
	digest := hash.Sum(nil)

	err = rsa.VerifyPKCS1v15(pub, cryptoHash, digest, ds)
	if err != nil {
		return NewErrSigNotValid(err)
	}
	return nil
}
func (a AuthPubTktImpl) decrypt(encTkt string) (string, error) {
	data, err := a.openSSL.DecryptString(
		a.options.TKTCypherTicketsWithPasswd,
		encTkt,
		EncMethod(strings.ToUpper(a.options.TKTCypherTicketsMethod)))
	if err != nil {
		return "", err
	}
	return string(data), nil
}

func (a AuthPubTktImpl) GenerateSignature(ticket *Ticket) (string, error) {
	if len(a.options.TKTAuthPrivateKey) == 0 {
		return "", errors.New("configuration is lacking TKTAuthPrivateKey, cannot sign")
	}
	if strings.Contains(a.options.TKTAuthDigest,"sha") { return a.signRsa(ticket)}
	if a.options.TKTAuthDigest == "dss1" { return a.signDsa(ticket) }
	return "", fmt.Errorf("signature type %s unsupported", a.options.TKTAuthDigest)
}
func (a AuthPubTktImpl) signRsa(ticket *Ticket) (string, error) {
	hash, htype, err := FindHash(a.options.TKTAuthDigest)
	if err != nil {
		return "", fmt.Errorf("error finding hash: %s",err)
	}

	tokenData := ticket.DataString()
	hash.Write([]byte(tokenData))
	sum := hash.Sum(nil)
	_ = sum
	if a.rsaPrivKey == nil {
		if !strings.Contains(a.options.TKTAuthPrivateKey,"RSA PRIVATE") {
			return "", fmt.Errorf("TKTAuthPrivateKey does not contain PEM-encoded RSA key")
		}
		block, _ := pem.Decode([]byte(a.options.TKTAuthPrivateKey))
		if block == nil {
			// do not return content the remainder here as that might potentially expose privkey
			return "", fmt.Errorf("could not decode PEM-encoded TKTAuthPrivateKey")
		}
		cert, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return "", fmt.Errorf("error parsing private key: %s", err)
		}
		a.rsaPrivKey = cert
		a.rsaPrivKey.Precompute()
	}
	signature,err := rsa.SignPKCS1v15(rand.Reader, a.rsaPrivKey,htype, sum)

	if err != nil {
		return "", err
	}
	return tokenData + ";sig=" + base64.StdEncoding.EncodeToString(signature),nil
}


func (a AuthPubTktImpl) signDsa(ticket *Ticket) (string, error) {
	hash, _ , err := FindHash("sha1")
	if err != nil {
		return "", fmt.Errorf("error finding hash: %s",err)
	}

	tokenData := ticket.DataString()
	hash.Write([]byte(tokenData))
	sum := hash.Sum(nil)
	_ = sum
	if a.dsaPrivKey == nil {
		if !strings.Contains(a.options.TKTAuthPrivateKey,"DSA PRIVATE") {
			return "", fmt.Errorf("TKTAuthPrivateKey does not contain PEM-encoded DSA key")
		}
		key, err := ssh.ParseRawPrivateKey([]byte(a.options.TKTAuthPrivateKey))
		if err != nil {
			return "", fmt.Errorf("couldn't parse DSA key: %s", err)
		}
		switch v := key.(type) {
		case *dsa.PrivateKey:
			a.dsaPrivKey = v
		default:
			return "", fmt.Errorf("expected DSA key, got: %T", v)
		}
	}

	r,s,err := dsa.Sign(rand.Reader, a.dsaPrivKey,sum)
	if err != nil {
		return "", fmt.Errorf("error while DSA signing: %s", err)
	}
	sig := PointsToDER(r,s)
	return tokenData + ";sig=" + base64.StdEncoding.EncodeToString(sig),nil
}


func asnIntegerPrefix(data []byte)  []byte {
	// ASN encodes zero as just a single byte
	if len(data) == 0 {
		data = []byte{0}
	}
	// and encode numbers between -128-127 also as single byte.
	if data[0] & 128 != 0 {
		paddedBytes := make([]byte, len(data)+1)
		copy(paddedBytes[1:], data)
		data = paddedBytes
	}
	return data
}

// Convert an ECDSA signature (points R and S) to a byte array using ASN.1 DER encoding.
// This is a port of Bitcore's Key.rs2DER method.
func PointsToDER(r, s *big.Int) []byte {
	// Ensure MSB doesn't break big endian encoding in DER sigs

	rb := asnIntegerPrefix(r.Bytes())
	sb := asnIntegerPrefix(s.Bytes())

	// DER encoding:
	// 0x30 + z + 0x02 + len(rb) + rb + 0x02 + len(sb) + sb
	length := 2 + len(rb) + 2 + len(sb)

	der := append([]byte{0x30, byte(length), 0x02, byte(len(rb))}, rb...)
	der = append(der, 0x02, byte(len(sb)))
	der = append(der, sb...)

	return der
}