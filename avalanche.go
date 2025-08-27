/*******************************************************************************
*   (c) 2018 - 2023 Zondax AG
*
*  Licensed under the Apache License, Version 2.0 (the "License");
*  you may not use this file except in compliance with the License.
*  You may obtain a copy of the License at
*
*      http://www.apache.org/licenses/LICENSE-2.0
*
*  Unless required by applicable law or agreed to in writing, software
*  distributed under the License is distributed on an "AS IS" BASIS,
*  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*  See the License for the specific language governing permissions and
*  limitations under the License.
// ********************************************************************************/

package ledger_avalanche_go

import (
	"errors"
	"fmt"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/ecdsa"
	ledger_go "github.com/zondax/ledger-go"
)

// FindLedgerAvalancheApp FindLedgerAvalancheUserApp finds a Avax user app running in a ledger device
func FindLedgerAvalancheApp() (_ *LedgerAvalanche, rerr error) {
	ledgerAdmin := ledger_go.NewLedgerAdmin()
	ledgerAPI, err := ledgerAdmin.Connect(0)
	if err != nil {
		return nil, err
	}

	defer func() {
		if rerr != nil {
			_ = ledgerAPI.Close()
		}
	}()

	app := &LedgerAvalanche{ledgerAPI, VersionInfo{}}
	appVersion, err := app.GetVersion()
	if err != nil {
		if err.Error() == "[APDU_CODE_CLA_NOT_SUPPORTED] CLA not supported" {
			err = errors.New("are you sure the Avalanche app is open?")
		}
		return nil, err
	}

	if err := app.CheckVersion(*appVersion); err != nil {
		return nil, err
	}

	return app, err
}

// Close closes a connection with the Avalanche user app
func (ledger *LedgerAvalanche) Close() error {
	return ledger.api.Close()
}

// CheckVersion returns true if the App version is supported by this library
func (ledger *LedgerAvalanche) CheckVersion(ver VersionInfo) error {
	version, err := ledger.GetVersion()
	if err != nil {
		return err
	}

	return CheckVersion(*version, ver)
}

// GetVersion returns the current version of the Avalanche user app
func (ledger *LedgerAvalanche) GetVersion() (*VersionInfo, error) {
	message := []byte{CLA, INS_GET_VERSION, 0, 0, 0}
	response, err := ledger.api.Exchange(message)
	if err != nil {
		return nil, err
	}

	if len(response) < 7 {
		return nil, errors.New("invalid response")
	}

	ledger.version = VersionInfo{
		AppMode: response[0],
		Major:   response[2], // Skip byte 1, use byte 2
		Minor:   response[4], // Skip byte 3, use byte 4
		Patch:   response[6], // Skip byte 5, use byte 6
	}

	return &ledger.version, nil
}

// GetPubKey returns the pubkey and hash
func (ledger *LedgerAvalanche) GetPubKey(path string, show bool, hrp string, chainid string) (*ResponseAddr, error) {
	if len(hrp) > 83 {
		return nil, errors.New("hrp len should be < 83 chars")
	}

	serializedHRP, err := SerializeHrp(hrp)
	if err != nil {
		return nil, err
	}

	serializedPath, err := SerializePath(path)
	if err != nil {
		return nil, err
	}

	serializedChainID, err := SerializeChainID(chainid)
	if err != nil {
		return nil, err
	}

	p1 := byte(P1_ONLY_RETRIEVE)
	if show {
		p1 = byte(P1_SHOW_ADDRESS_IN_DEVICE)
	}

	// Prepare message
	payload := []byte{CLA, INS_GET_ADDR, p1, 0, 0}
	headerLen := len(payload)

	payload = append(payload, serializedHRP...)
	payload = append(payload, serializedChainID...)
	payload = append(payload, serializedPath...)
	payload[4] = byte(len(payload) - headerLen) // update length

	response, err := ledger.api.Exchange(payload)
	if err != nil {
		return nil, err
	}

	if len(response) < 35+len(hrp) {
		return nil, errors.New("invalid response")
	}

	// [publicKeyLen | publicKey | hash | address | errorCode]
	publicKeyLen := response[0]
	publicKey := append([]byte{}, response[1:publicKeyLen+1]...)
	hash := append([]byte{}, response[publicKeyLen+1:publicKeyLen+1+20]...)
	address := string(response[publicKeyLen+1+20:])

	return &ResponseAddr{publicKey, hash, address}, nil
}

// GetExtPubKey returns the extended pubkey
func (ledger *LedgerAvalanche) GetExtPubKey(path string, show bool, hrp string, chainid string) ([]byte, []byte, error) {
	if len(hrp) > 83 {
		return nil, nil, errors.New("hrp len should be < 83 chars")
	}

	serializedHRP, err := SerializeHrp(hrp)
	if err != nil {
		return nil, nil, err
	}

	serializedPath, err := SerializePath(path)
	if err != nil {
		return nil, nil, err
	}

	serializedChainID, err := SerializeChainID(chainid)
	if err != nil {
		return nil, nil, err
	}

	p1 := byte(P1_ONLY_RETRIEVE)
	if show {
		p1 = byte(P1_SHOW_ADDRESS_IN_DEVICE)
	}

	// Prepare message
	payload := []byte{CLA, INS_GET_EXTENDED_PUBLIC_KEY, p1, 0, 0}
	headerLen := len(payload)
	payload = append(payload, serializedHRP...)
	payload = append(payload, serializedChainID...)
	payload = append(payload, serializedPath...)
	payload[4] = byte(len(payload) - headerLen) // update length

	response, err := ledger.api.Exchange(payload)
	if err != nil {
		return nil, nil, err
	}

	if len(response) < 32 {
		return nil, nil, errors.New("invalid response")
	}

	publicKeyLen := response[0]
	publicKey := append([]byte{}, response[1:publicKeyLen+1]...)
	chainCode := append([]byte{}, response[publicKeyLen+1:]...)

	return publicKey, chainCode, nil
}

func (ledger *LedgerAvalanche) Sign(pathPrefix string, signingPaths []string, message []byte, changePaths []string) (*ResponseSign, error) {
	paths := signingPaths
	if changePaths != nil {
		paths = append(paths, changePaths...)
		paths = RemoveDuplicates(paths)
	}

	serializedPath, err := SerializePath(pathPrefix)
	if err != nil {
		return nil, err
	}

	msg := ConcatMessageAndChangePath(message, paths)

	// Prepare chunks using ledger-go's PrepareChunks function
	chunks := ledger_go.PrepareChunks(serializedPath, msg)

	// Custom error handler for Avalanche-specific errors
	errorHandler := func(err error, response []byte, instruction byte) error {
		if err.Error() == "[APDU_CODE_BAD_KEY_HANDLE] The parameters in the data field are incorrect" {
			// In this special case, we can extract additional info
			return fmt.Errorf("%w extra_info=(%s)", err, string(response))
		}
		if err.Error() == "[APDU_CODE_DATA_INVALID] Referenced data reversibly blocked (invalidated)" {
			return fmt.Errorf("%w extra_info=(%s)", err, string(response))
		}
		return err
	}

	// Process chunks using ledger-go's ProcessChunks function
	_, err = ledger_go.ProcessChunks(ledger.api, chunks, CLA, INS_SIGN, FIRST_MESSAGE, errorHandler)
	if err != nil {
		return nil, err
	}

	// Transaction was approved so start iterating over signing_paths to sign
	// and collect each signature
	return SignAndCollect(signingPaths, ledger)
}

func (ledger *LedgerAvalanche) SignHash(pathPrefix string, signingPaths []string, hash []byte) (*ResponseSign, error) {
	if len(hash) != HASH_LEN {
		return nil, errors.New("wrong hash size")
	}

	serializedPath, err := SerializePath(pathPrefix)
	if err != nil {
		return nil, err
	}

	payload := []byte{CLA, INS_SIGN_HASH, FIRST_MESSAGE, byte(0x00), byte(len(serializedPath) + len(hash))}
	payload = append(payload, serializedPath...)
	payload = append(payload, hash...)
	firstResponse, err := ledger.api.Exchange(payload)
	if err != nil {
		return nil, errors.New("command rejected")
	}
	if len(firstResponse) != 0 {
		return nil, errors.New("wrong response")
	}

	return SignAndCollect(signingPaths, ledger)
}

func SignAndCollect(signingPaths []string, ledger *LedgerAvalanche) (*ResponseSign, error) {
	// Where each pair path_suffix, signature are stored
	signatures := make(map[string][]byte)

	for idx, suffix := range signingPaths {
		pathBuf, err := SerializePathSuffix(suffix)
		if err != nil {
			return nil, err
		}

		p1 := LAST_MESSAGE
		if idx < len(signingPaths)-1 {
			p1 = NEXT_MESSAGE
		}

		// Send path to sign hash that should be in device's ram memory
		payload := []byte{CLA, INS_SIGN_HASH, byte(p1), byte(0x00), byte(len(pathBuf))}
		payload = append(payload, pathBuf...)
		response, err := ledger.api.Exchange(payload)
		if err != nil {
			return nil, err
		}
		signatures[suffix] = response
	}

	return &ResponseSign{nil, signatures}, nil
}

func (ledger *LedgerAvalanche) VerifyMultipleSignatures(response ResponseSign, messageHash []byte, rootPath string, signingPaths []string, hrp string, chainID string) error {
	if len(response.Signature) != len(signingPaths) {
		return errors.New("sizes of signatures and paths don't match")
	}

	for _, suffix := range signingPaths {
		path := fmt.Sprintf("%s/%s", rootPath, suffix)

		addr, err := ledger.GetPubKey(path, false, hrp, chainID)
		if err != nil {
			return errors.New("error getting the pubkey")
		}

		hexString := fmt.Sprintf("%x", addr.PublicKey)
		fmt.Println(hexString)

		sigLen := len(response.Signature[suffix])
		verified := VerifySignature(addr.PublicKey, messageHash, response.Signature[suffix][:sigLen-1])

		if !verified {
			return errors.New("[VerifySig] Error verifying signature: ")
		}
	}
	return nil
}

// VerifySignature checks that the given public key created signature over hash.
// The public key should be in compressed (33 bytes) or uncompressed (65 bytes) format.
// The signature should have the 64 byte [R || S] format.
func VerifySignature(pubkey, hash, signature []byte) bool {
	if len(signature) != 64 {
		return false
	}
	var r, s btcec.ModNScalar
	if r.SetByteSlice(signature[:32]) {
		return false // overflow
	}
	if s.SetByteSlice(signature[32:]) {
		return false
	}
	sig := ecdsa.NewSignature(&r, &s)
	key, err := btcec.ParsePubKey(pubkey)
	if err != nil {
		return false
	}
	// Reject malleable signatures. libsecp256k1 does this check but btcec doesn't.
	if s.IsOverHalfOrder() {
		return false
	}
	return sig.Verify(hash, key)
}
