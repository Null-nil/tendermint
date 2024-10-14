//go:build !libsecp256k1
// +build !libsecp256k1

package secp256k1

import (
	"math/big"
	"testing"

	secp256k1 "github.com/btcsuite/btcd/btcec/v2"
	"github.com/stretchr/testify/require"
)

// Ensure that signature verification works, and that
// non-canonical signatures fail.
// Note: run with CGO_ENABLED=0 or go test -tags !cgo.
func TestSignatureVerificationAndRejectUpperS(t *testing.T) {
	msg := []byte("We have lingered long enough on the shores of the cosmic ocean.")
	for i := 0; i < 500; i++ {
		priv := GenPrivKey()
		sigStr, err := priv.Sign(msg)
		require.NoError(t, err)
		sig := signatureFromBytes(sigStr)
		sigSerialize := sig.Serialize()
		_, SigS, _ := DeSerializeDerEncoding(sigSerialize)
		sigBigIntS := big.NewInt(0).SetBytes(SigS)
		require.False(t, sigBigIntS.Cmp(secp256k1halfN) > 0)

		pub := priv.PubKey()
		require.True(t, pub.VerifyBytes(msg, sigStr))

		// malleate:
		sigBigIntS.Sub(secp256k1.S256().CurveParams.N, sigBigIntS)
		require.True(t, sigBigIntS.Cmp(secp256k1halfN) > 0)
		malSigStr := serializeSig(sig)

		require.False(t, pub.VerifyBytes(msg, malSigStr),
			"VerifyBytes incorrect with malleated & invalid S. sig=%v, key=%v",
			sig,
			priv,
		)
	}
}
