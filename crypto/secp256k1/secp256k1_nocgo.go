//go:build !libsecp256k1
// +build !libsecp256k1

package secp256k1

import (
	"encoding/asn1"
	"fmt"
	secp256k1 "github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/ecdsa"
	"math/big"

	"github.com/tendermint/tendermint/crypto"
)

// used to reject malleable signatures
// see:
//   - https://github.com/ethereum/go-ethereum/blob/f9401ae011ddf7f8d2d95020b7446c17f8d98dc1/crypto/signature_nocgo.go#L90-L93
//   - https://github.com/ethereum/go-ethereum/blob/f9401ae011ddf7f8d2d95020b7446c17f8d98dc1/crypto/crypto.go#L39
var secp256k1halfN = new(big.Int).Rsh(secp256k1.S256().N, 1)

// Sign creates an ECDSA signature on curve Secp256k1, using SHA256 on the msg.
// The returned signature will be of the form R || S (in lower-S form).
func (privKey PrivKeySecp256k1) Sign(msg []byte) ([]byte, error) {
	priv, _ := secp256k1.PrivKeyFromBytes(privKey[:])
	sig := ecdsa.Sign(priv, crypto.Sha256(msg))
	sigBytes := serializeSig(sig)
	if sigBytes == nil {
		return nil, fmt.Errorf("serialize sig error")
	}
	return sigBytes, nil
}
func DeSerializeDerEncoding(derSig []byte) ([]byte, []byte, error) {
	var seq struct {
		R *big.Int `asn1:"optional"`
		S *big.Int `asn1:"optional"`
	}
	_, err := asn1.Unmarshal(derSig, &seq)
	if err != nil {
		return nil, nil, err
	}
	return seq.R.Bytes(), seq.S.Bytes(), nil
}

/*
func DeSerializeDerEncoding(derSig []byte) ([]byte, []byte, error) {
	if derSig[0] != 0x30 {
		return nil, nil, fmt.Errorf("invalid der signature format: derSig[0]")
	}
	if int(derSig[1])+2 != len(derSig) {
		return nil, nil, fmt.Errorf("invalid der signature format: derSig[1]")
	}

	if derSig[2] != 0x2 {
		return nil, nil, fmt.Errorf("invalid der signature format: derSig[2]")
	}
	rl := uint(derSig[3])
	if rl > 33 {
		return nil, nil, fmt.Errorf("invalid der signature format: derSig[3]")
	}
	r := derSig[4 : 4+rl]

	if derSig[4+rl] != 0x2 {
		return nil, nil, fmt.Errorf("invalid der signature format: derSig[4+rl]")
	}
	sl := uint(derSig[5+rl])
	if sl > 33 {
		return nil, nil, fmt.Errorf("invalid der signature format: derSig[5+rl]")
	}
	s := derSig[6+rl : 6+rl+sl]

	var rBytes []byte
	if len(r) == 33 {
		r = r[1:]
	} else {
		cnt := 32 - len(r)
		repeated := strings.Repeat(string(byte(0x0)), cnt)
		rBytes = append(rBytes, []byte(repeated)...)
		rBytes = append(rBytes, r...)
	}

	var sBytes []byte
	if len(s) == 33 {
		s = s[1:]
	} else {
		cnt := 32 - len(s)
		repeated := strings.Repeat(string(byte(0x0)), cnt)
		sBytes = append(sBytes, []byte(repeated)...)
		sBytes = append(sBytes, s...)
	}

	return rBytes, sBytes, nil
}*/

// VerifyBytes verifies a signature of the form R || S.
// It rejects signatures which are not in lower-S form.
func (pubKey PubKeySecp256k1) VerifyBytes(msg []byte, sigStr []byte) bool {
	if len(sigStr) != 64 {
		return false
	}
	pub, err := secp256k1.ParsePubKey(pubKey[:])
	if err != nil {
		return false
	}
	// parse the signature:
	signature := signatureFromBytes(sigStr)
	// Reject malleable signatures. libsecp256k1 does this check but btcec doesn't.
	// see: https://github.com/ethereum/go-ethereum/blob/f9401ae011ddf7f8d2d95020b7446c17f8d98dc1/crypto/signature_nocgo.go#L90-L93
	sigSerialize := signature.Serialize()
	_, SigS, err := DeSerializeDerEncoding(sigSerialize)
	if err != nil {
		return false
	}
	sigBigIntS := big.NewInt(0).SetBytes(SigS)
	if sigBigIntS.Cmp(secp256k1halfN) > 0 {
		return false
	}
	return signature.Verify(crypto.Sha256(msg), pub)
}

// Read Signature struct from R || S. Caller needs to ensure
// that len(sigStr) == 64.
func signatureFromBytes(sigStr []byte) *ecdsa.Signature {
	var r, s secp256k1.ModNScalar
	r.SetByteSlice(sigStr[:32])
	s.SetByteSlice(sigStr[32:64])
	tempSig := ecdsa.NewSignature(&r, &s)
	return tempSig
}

// Serialize signature to R || S.
// R, S are padded to 32 bytes respectively.
func serializeSig(sig *ecdsa.Signature) []byte {
	sigSerialize := sig.Serialize()

	SigR, SigS, err := DeSerializeDerEncoding(sigSerialize)
	if err != nil {
		return nil
	}

	/*
		sigBigIntS := big.NewInt(0).SetBytes(SigS)
		rBytes := sig.R.Bytes()
		sBytes := sig.S.Bytes()*/
	sigBytes := make([]byte, 64)
	// 0 pad the byte arrays from the left if they aren't big enough.
	copy(sigBytes[32-len(SigR):32], SigR)
	copy(sigBytes[64-len(SigS):64], SigS)
	return sigBytes
}
