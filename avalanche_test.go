/*******************************************************************************
*   (c) 2018 - 2022 ZondaX AG
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
********************************************************************************/

package ledger_avalanche_go

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Ledger Test Mnemonic: equip will roof matter pink blind book anxiety banner elbow sun young

func Test_UserFindLedger(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping test in short mode.")
	}
	userApp, err := FindLedgerAvalancheApp()
	if err != nil {
		t.Fatalf("error: %v", err.Error())
	}

	assert.NotNil(t, userApp)
	defer func() { _ = userApp.Close() }()
}

func Test_UserGetVersion(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping test in short mode.")
	}
	userApp, err := FindLedgerAvalancheApp()
	if err != nil {
		t.Fatalf("error: %v", err.Error())
	}
	defer func() { _ = userApp.Close() }()

	version, err := userApp.GetVersion()
	require.Nil(t, err, "Detected error")
	fmt.Println(version)

	assert.Equal(t, uint8(0x0), version.AppMode, "TESTING MODE ENABLED!!")
	assert.Equal(t, uint8(0x1), version.Major, "Wrong Major version")
	assert.Equal(t, uint8(0x3), version.Minor, "Wrong Minor version")
	assert.Equal(t, uint8(0x8), version.Patch, "Wrong Patch version")
}

func Test_UserGetPublicKey(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping test in short mode.")
	}
	userApp, err := FindLedgerAvalancheApp()
	if err != nil {
		t.Fatalf("error: %v", err.Error())
	}
	defer func() { _ = userApp.Close() }()

	path := "m/44'/9000'/0'/0/0"
	hrp := ""
	chainID := ""
	showAddress := false

	addr, err := userApp.GetPubKey(path, showAddress, hrp, chainID)
	if err != nil {
		t.Fatalf("Detected error, err: %s\n", err.Error())
	}

	assert.Equal(t, 33, len(addr.PublicKey),
		"Public key has wrong length: %x, expected length: %x\n", addr.PublicKey, 66)
	fmt.Printf("PUBLIC KEY: %x\n", addr.PublicKey)

	assert.Equal(t, 20, len(addr.Hash),
		"Public key hash has wrong length: %x, expected length: %x\n", addr.Hash, 40)
	fmt.Printf("HASH: %x\n", addr.Hash)

	assert.Equal(t, len("P-avax1tlq4m9js4ckqvz9umfz7tjxna3yysm79r2jz8e"),
		len(addr.Address),
		"Address has wrong length: %x, expected length: %x\n", addr.Address, 43)
	fmt.Printf("ADDRESS: %x\n", addr.Address)

	assert.Equal(t,
		"02c6f477ff8e7136de982f898f6bfe93136bbe8dada6c17d0cd369acce90036ac4",
		hex.EncodeToString(addr.PublicKey),
		"Unexpected publicKey")

	assert.Equal(t,
		"5fc15d9650ae2c0608bcda45e5c8d3ec48486fc5",
		hex.EncodeToString(addr.Hash),
		"Unexpected hash")

	assert.Equal(t,
		"P-avax1tlq4m9js4ckqvz9umfz7tjxna3yysm79r2jz8e",
		addr.Address,
		"Unexpected address")
}

func Test_UserGetPublicKeyETH(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping test in short mode.")
	}
	userApp, err := FindLedgerAvalancheApp()
	if err != nil {
		t.Fatalf("error: %v", err.Error())
	}
	defer func() { _ = userApp.Close() }()

	pathETH := "m/44'/60'/0'/0'/5"
	hrp := ""
	chainID := ""
	showAddress := false

	addr, err := userApp.GetPubKey(pathETH, showAddress, hrp, chainID)
	if err != nil {
		t.Fatalf("Detected error, err: %s\n", err.Error())
	}

	assert.Equal(t, 33, len(addr.PublicKey),
		"Public key has wrong length: %x, expected length: %x\n", addr.PublicKey, 33)
	fmt.Printf("PUBLIC KEY: %x\n", addr.PublicKey)

	assert.Equal(t, 20, len(addr.Hash),
		"Public key has wrong length: %x, expected length: %x\n", addr.Hash, 20)
	fmt.Printf("HASH: %x\n", addr.Hash)

	// FIXME: use proper test values
	assert.Equal(t,
		"024f1dd50f180bfd546339e75410b127331469837fa618d950f7cfb8be351b0020",
		hex.EncodeToString(addr.PublicKey),
		"Unexpected publicKey")

	assert.Equal(t,
		"1191eb25cba3b091d192e2f0c0c11b0ced949037",
		hex.EncodeToString(addr.Hash),
		"Unexpected hash")
}

func Test_UserPK_HDPaths(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping test in short mode.")
	}
	userApp, err := FindLedgerAvalancheApp()
	if err != nil {
		t.Fatalf("error: %v", err.Error())
	}
	defer func() { _ = userApp.Close() }()

	hrp := ""
	chainID := ""
	showAddress := false

	expected := []string{
		"034fef9cd7c4c63588d3b03feb5281b9d232cba34d6f3d71aee59211ffbfe1fe87",
		"0260d0487a3dfce9228eee2d0d83a40f6131f551526c8e52066fe7fe1e4a509666",
		"03a2670393d02b162d0ed06a08041e80d86be36c0564335254df7462447eb69ab3",
		"033222fc61795077791665544a90740e8ead638a391a3b8f9261f4a226b396c042",
		"03f577473348d7b01e7af2f245e36b98d181bc935ec8b552cde5932b646dc7be04",
		"0222b1a5486be0a2d5f3c5866be46e05d1bde8cda5ea1c4c77a9bc48d2fa2753bc",
		"0377a1c826d3a03ca4ee94fc4dea6bccb2bac5f2ac0419a128c29f8e88f1ff295a",
		"031b75c84453935ab76f8c8d0b6566c3fcc101cc5c59d7000bfc9101961e9308d9",
		"038905a42433b1d677cc8afd36861430b9a8529171b0616f733659f131c3f80221",
		"038be7f348902d8c20bc88d32294f4f3b819284548122229decd1adf1a7eb0848b",
	}

	for i := uint32(0); i < 10; i++ {
		path := fmt.Sprintf("m/44'/9000'/0'/0/%d", i)

		addr, err := userApp.GetPubKey(path, showAddress, hrp, chainID)
		if err != nil {
			t.Fatalf("Detected error, err: %s\n", err.Error())
		}
		publicKey := addr.PublicKey
		hash := addr.Hash

		assert.Equal(
			t,
			33,
			len(publicKey),
			"Public key has wrong length: %x, expected length: %x\n", publicKey, 33)

		assert.Equal(
			t,
			expected[i],
			hex.EncodeToString(publicKey),
			"Public key 44'/118'/0'/0/%d does not match\n", i)

		assert.Equal(t, 20, len(hash),
			"Public key has wrong length: %x, expected length: %x\n", hash, 20)
		fmt.Printf("HASH: %x\n", hash)
	}
}

func Test_UserSign(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping test in short mode.")
	}
	userApp, err := FindLedgerAvalancheApp()
	if err != nil {
		t.Fatalf("error: %v", err.Error())
	}
	defer func() { _ = userApp.Close() }()

	rootPath := "m/44'/9000'/0'"
	signers := []string{"0/0", "5/8"}

	simpleTransferData := []byte{
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x30, 0x39, 0x9d, 0x07, 0x75, 0xf4, 0x50,
		0x60, 0x4b, 0xd2, 0xfb, 0xc4, 0x9c, 0xe0, 0xc5, 0xc1, 0xc6, 0xdf, 0xeb, 0x2d, 0xc2, 0xac,
		0xb8, 0xc9, 0x2c, 0x26, 0xee, 0xae, 0x6e, 0x6d, 0xf4, 0x50, 0x2b, 0x19, 0xd8, 0x91, 0xad,
		0x56, 0x05, 0x6d, 0x9c, 0x01, 0xf1, 0x8f, 0x43, 0xf5, 0x8b, 0x5c, 0x78, 0x4a, 0xd0, 0x7a,
		0x4a, 0x49, 0xcf, 0x3d, 0x1f, 0x11, 0x62, 0x38, 0x04, 0xb5, 0xcb, 0xa2, 0xc6, 0xbf, 0x00,
		0x00, 0x00, 0x01, 0xf1, 0xe1, 0xd1, 0xc1, 0xb1, 0xa1, 0x91, 0x81, 0x71, 0x61, 0x51, 0x41,
		0x31, 0x21, 0x11, 0x01, 0xf0, 0xe0, 0xd0, 0xc0, 0xb0, 0xa0, 0x90, 0x80, 0x70, 0x60, 0x50,
		0x40, 0x30, 0x20, 0x10, 0x00, 0x00, 0x00, 0x00, 0x05, 0xdb, 0xcf, 0x89, 0x0f, 0x77, 0xf4,
		0x9b, 0x96, 0x85, 0x76, 0x48, 0xb7, 0x2b, 0x77, 0xf9, 0xf8, 0x29, 0x37, 0xf2, 0x8a, 0x68,
		0x70, 0x4a, 0xf0, 0x5d, 0xa0, 0xdc, 0x12, 0xba, 0x53, 0xf2, 0xdb, 0x00, 0x00, 0x00, 0x05,
		0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
		0x00, 0x00, 0x00, 0xdb, 0xcf, 0x89, 0x0f, 0x77, 0xf4, 0x9b, 0x96, 0x85, 0x76, 0x48, 0xb7,
		0x2b, 0x77, 0xf9, 0xf8, 0x29, 0x37, 0xf2, 0x8a, 0x68, 0x70, 0x4a, 0xf0, 0x5d, 0xa0, 0xdc,
		0x12, 0xba, 0x53, 0xf2, 0xdb,
	}

	response, err := userApp.Sign(rootPath, signers, simpleTransferData, nil)
	if err != nil {
		t.Fatalf("Detected error, err: %s\n", err.Error())
	}

	if len(response.Signature) > 10000 {
		return
	}

	hrp := ""
	chainID := ""
	h := sha256.New()
	h.Write(simpleTransferData)
	msgHash := h.Sum(nil)

	err = userApp.VerifyMultipleSignatures(*response, msgHash, rootPath, signers, hrp, chainID)
	if err != nil {
		t.Fatalf("Detected error, err: %s\n", err.Error())
	}
}

func Test_UserSignHash(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping test in short mode.")
	}
	userApp, err := FindLedgerAvalancheApp()
	if err != nil {
		t.Fatalf("error: %v", err.Error())
	}
	defer func() { _ = userApp.Close() }()

	rootPath := "m/44'/9000'/0'"
	signingList := []string{"0/0", "4/8"}

	message := "AvalancheApp"
	h := sha256.New()
	h.Write([]byte(message))
	hash := h.Sum(nil)

	response, err := userApp.SignHash(rootPath, signingList, hash)
	if err != nil {
		t.Fatalf("Detected error, err: %s\n", err.Error())
	}

	hrp := ""
	chainID := ""
	err = userApp.VerifyMultipleSignatures(*response, hash, rootPath, signingList, hrp, chainID)
	if err != nil {
		t.Fatalf("Detected error, err: %s\n", err.Error())
	}
}
