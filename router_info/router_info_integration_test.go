package router_info

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-i2p/common/data"
	"github.com/go-i2p/common/router_address"
	"github.com/go-i2p/common/signature"
	"github.com/samber/oops"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

//
// Round-trip serialization
//

func TestRoundTripByteFidelity(t *testing.T) {
	ri, err := generateTestRouterInfo(t, time.Now())
	require.NoError(t, err)

	bytes1, err := ri.Bytes()
	require.NoError(t, err)

	ri2, remainder, err := ReadRouterInfo(bytes1)
	require.NoError(t, err)
	assert.Empty(t, remainder)

	bytes2, err := ri2.Bytes()
	require.NoError(t, err)

	assert.Equal(t, bytes1, bytes2)
}

func TestRoundTripSerialization(t *testing.T) {
	ri, err := generateTestRouterInfo(t, time.Now())
	require.NoError(t, err)

	bytes1, err := ri.Bytes()
	require.NoError(t, err)
	require.NotEmpty(t, bytes1)

	ri2, remainder, err := ReadRouterInfo(bytes1)
	require.NoError(t, err)
	assert.Empty(t, remainder)

	bytes2, err := ri2.Bytes()
	require.NoError(t, err)

	assert.Equal(t, bytes1, bytes2)
	assert.Equal(t, ri.RouterAddressCount(), ri2.RouterAddressCount())
	assert.Equal(t, ri.PeerSize(), ri2.PeerSize())
}

//
// Verify signature integration
//

func TestVerifySignatureValid(t *testing.T) {
	ri, err := generateTestRouterInfo(t, time.Now())
	require.NoError(t, err)

	valid, err := ri.VerifySignature()
	assert.NoError(t, err)
	assert.True(t, valid)
}

func TestVerifySignatureDetectsTampering(t *testing.T) {
	ri, err := generateTestRouterInfo(t, time.Now())
	require.NoError(t, err)

	tampered := data.Date{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01}
	ri.published = &tampered

	valid, err := ri.VerifySignature()
	assert.NoError(t, err)
	assert.False(t, valid)
}

func TestVerifySignaturePreHashRoundTrip(t *testing.T) {
	ri, err := generateTestRouterInfo(t, time.Now())
	require.NoError(t, err)

	valid, err := ri.VerifySignature()
	assert.NoError(t, err)
	assert.True(t, valid)
}

// TestVerifySignatureRoundTrip creates a RouterInfo, serializes it via Bytes(),
// parses it via ReadRouterInfo(), and verifies the signature on the parsed result.
// This is the most security-critical code path in the package.
func TestVerifySignatureRoundTrip(t *testing.T) {
	ri, err := generateTestRouterInfo(t, time.Now())
	require.NoError(t, err)

	// Step 1: Verify signature on original
	valid, err := ri.VerifySignature()
	require.NoError(t, err)
	require.True(t, valid, "signature should be valid on original RouterInfo")

	// Step 2: Serialize to bytes
	riBytes, err := ri.Bytes()
	require.NoError(t, err)
	require.NotEmpty(t, riBytes)

	// Step 3: Parse from bytes
	parsed, remainder, err := ReadRouterInfo(riBytes)
	require.NoError(t, err)
	assert.Empty(t, remainder, "should have no remaining bytes")

	// Step 4: Verify signature on parsed result
	valid, err = parsed.VerifySignature()
	assert.NoError(t, err)
	assert.True(t, valid, "signature should be valid on parsed RouterInfo")
}

//
// Bytes() options serialization consistency
//

func TestBytesOptionsConsistency(t *testing.T) {
	ri, err := generateTestRouterInfo(t, time.Now())
	require.NoError(t, err)

	fullBytes, err := ri.Bytes()
	require.NoError(t, err)

	serializedData, err := ri.serializeWithoutSignature()
	require.NoError(t, err)

	sigBytes := ri.signature.Bytes()
	combined := append(serializedData, sigBytes...)
	assert.Equal(t, fullBytes, combined)
}

//
// 10K real router info file processing
//

func consolidateNetDb(sourcePath, destPath string) error {
	if err := os.MkdirAll(destPath, 0o755); err != nil {
		return oops.Errorf("failed to create destination directory: %v", err)
	}
	return filepath.Walk(sourcePath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return oops.Errorf("error accessing path %q: %v", path, err)
		}
		if info.IsDir() {
			return nil
		}
		if strings.HasPrefix(info.Name(), "routerInfo-") && strings.HasSuffix(info.Name(), ".dat") {
			return copyFile(path, filepath.Join(destPath, info.Name()))
		}
		return nil
	})
}

func copyFile(src, dst string) error {
	sourceFile, err := os.Open(src)
	if err != nil {
		return err
	}
	defer sourceFile.Close()
	destFile, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer destFile.Close()
	_, err = io.Copy(destFile, sourceFile)
	return err
}

func consolidateAllNetDbs(tempDir string) error {
	i2pPath := filepath.Join(os.Getenv("HOME"), ".i2p/netDb")
	i2pdPath := filepath.Join(os.Getenv("HOME"), ".i2pd/netDb")
	if err := os.MkdirAll(tempDir, 0o755); err != nil {
		return oops.Errorf("failed to create temp directory: %v", err)
	}
	if _, err := os.Stat(i2pPath); err == nil {
		if err := consolidateNetDb(i2pPath, tempDir); err != nil {
			fmt.Printf("Warning: Error processing I2P netDb: %v\n", err)
		}
	}
	if _, err := os.Stat(i2pdPath); err == nil {
		if err := consolidateNetDb(i2pdPath, tempDir); err != nil {
			fmt.Printf("Warning: Error processing I2Pd netDb: %v\n", err)
		}
	}
	return nil
}

func cleanupTempDir(path string) error {
	if err := os.RemoveAll(path); err != nil {
		return oops.Errorf("failed to cleanup temporary directory %s: %v", path, err)
	}
	return nil
}

func createTempNetDbDir() (string, error) {
	baseDir, _ := os.Getwd()
	baseDir = filepath.Join(baseDir, "temp")
	timestamp := time.Now().Unix()
	dirName := fmt.Sprintf("go-i2p-testfiles-%d", timestamp)
	tempDir := filepath.Join(baseDir, dirName)
	err := os.MkdirAll(tempDir, 0o755)
	if err != nil {
		return "", oops.Errorf("failed to create temporary directory: %v", err)
	}
	return tempDir, nil
}

func Test10K(t *testing.T) {
	if err := checkNetDbDirectoriesExist(t); err != nil {
		return
	}
	tempDir, targetDir, err := setupTestDirectories(t)
	if err != nil {
		t.Fatalf("Failed to setup test directories: %v", err)
	}
	if err := processAllRouterInfoFiles(t, tempDir, targetDir); err != nil {
		t.Fatalf("Failed to process router info files: %v", err)
	}
	cleanupTestDirectories(t, tempDir, targetDir)
}

func checkNetDbDirectoriesExist(t *testing.T) error {
	i2pPath := filepath.Join(os.Getenv("HOME"), ".i2p/netDb")
	i2pdPath := filepath.Join(os.Getenv("HOME"), ".i2pd/netDb")
	if _, err := os.Stat(i2pPath); os.IsNotExist(err) {
		if _, err := os.Stat(i2pdPath); os.IsNotExist(err) {
			t.Skip("Neither .i2p nor .i2pd netDb directories exist, so we will skip.")
			return fmt.Errorf("test skipped")
		}
	}
	return nil
}

func setupTestDirectories(t *testing.T) (tempDir, targetDir string, err error) {
	tempDir, err = createTempNetDbDir()
	if err != nil {
		return "", "", fmt.Errorf("failed to create temp directory: %v", err)
	}
	if err := consolidateAllNetDbs(tempDir); err != nil {
		return "", "", fmt.Errorf("failed to consolidate netDbs: %v", err)
	}
	time.Sleep(1 * time.Second)
	targetDir, err = createTempNetDbDir()
	if err != nil {
		return "", "", fmt.Errorf("failed to create target directory: %v", err)
	}
	return tempDir, targetDir, nil
}

func processAllRouterInfoFiles(t *testing.T, tempDir, targetDir string) error {
	files, err := os.ReadDir(tempDir)
	if err != nil {
		return fmt.Errorf("failed to read temp directory: %v", err)
	}
	for d, file := range files {
		if shouldProcessFile(file) {
			if err := processRouterInfoFile(t, tempDir, targetDir, file, d); err != nil {
				t.Logf("Failed to process file %s: %v", file.Name(), err)
				return err
			}
		}
	}
	return nil
}

func shouldProcessFile(file os.DirEntry) bool {
	return !file.IsDir() && strings.HasPrefix(file.Name(), "routerInfo-")
}

func processRouterInfoFile(t *testing.T, tempDir, targetDir string, file os.DirEntry, fileIndex int) error {
	fmt.Println("RI LOAD: ", fileIndex, file.Name())
	fileData, err := readRouterInfoFile(tempDir, file.Name())
	if err != nil {
		return fmt.Errorf("failed to read file: %v", err)
	}
	routerInfo, err := parseRouterInfoData(fileData)
	if err != nil {
		return fmt.Errorf("failed to parse router info: %v", err)
	}
	gv, err := routerInfo.GoodVersion()
	if err != nil {
		t.Logf("RI goodness check failed, may be ephemeral: %s", err)
	}
	t.Logf("Router version is %s, Good: %v", routerInfo.RouterVersion(), gv)
	if err := writeRouterInfoFile(targetDir, file.Name(), routerInfo); err != nil {
		return fmt.Errorf("failed to write router info: %v", err)
	}
	return nil
}

func readRouterInfoFile(directory, filename string) ([]byte, error) {
	return os.ReadFile(filepath.Join(directory, filename))
}

func parseRouterInfoData(fileData []byte) (RouterInfo, error) {
	routerInfo, _, err := ReadRouterInfo(fileData)
	if err != nil {
		return RouterInfo{}, err
	}
	return routerInfo, nil
}

func writeRouterInfoFile(targetDir, filename string, routerInfo RouterInfo) error {
	routerBytes, err := routerInfo.Bytes()
	if err != nil {
		return fmt.Errorf("failed to serialize router info: %v", err)
	}
	err = os.WriteFile(filepath.Join(targetDir, filename), routerBytes, 0o644)
	if err != nil {
		return fmt.Errorf("failed to write file: %v", err)
	}
	return nil
}

func cleanupTestDirectories(t *testing.T, tempDir, targetDir string) {
	cleanupSingleDirectory(t, tempDir, "temp")
	cleanupSingleDirectory(t, targetDir, "target")
}

func cleanupSingleDirectory(t *testing.T, dir, dirType string) {
	if err := cleanupTempDir(dir); err != nil {
		log.WithError(err).Error("Failed to cleanup " + dirType + " directory")
		t.Errorf("Failed to cleanup %s directory: %v", dirType, err)
	}
}

//
// ReSign tests
//

// TestReSignAfterAddAddress verifies that ReSign produces a valid signature after
// AddAddress has invalidated the original one.
func TestReSignAfterAddAddress(t *testing.T) {
	keyPair := generateTestKeyPair(t)
	routerIdentity := assembleTestRouterIdentity(t, keyPair)

	ntcp2Addr, err := router_address.NewRouterAddress(3, time.Time{}, "NTCP2", map[string]string{
		"host": "203.0.113.1",
		"port": "9001",
	})
	require.NoError(t, err)

	ri, err := NewRouterInfo(
		routerIdentity,
		time.Now(),
		[]*router_address.RouterAddress{ntcp2Addr},
		map[string]string{"caps": "LfR", "router.version": "0.9.64"},
		&keyPair.ed25519PrivKey,
		signature.SIGNATURE_TYPE_EDDSA_SHA512_ED25519,
	)
	require.NoError(t, err)

	// Verify initial signature is valid.
	valid, err := ri.VerifySignature()
	require.NoError(t, err)
	require.True(t, valid, "initial signature should be valid")

	// Add an SSU2 address — this invalidates the signature.
	ssu2Addr, err := router_address.NewRouterAddress(7, time.Time{}, "SSU2", map[string]string{
		"host": "203.0.113.1",
		"port": "9002",
	})
	require.NoError(t, err)
	require.NoError(t, ri.AddAddress(ssu2Addr))

	// Signature field is now nil; Bytes() and VerifySignature() should error.
	_, err = ri.Bytes()
	assert.Error(t, err, "Bytes() should fail when signature is nil")

	_, err = ri.VerifySignature()
	assert.Error(t, err, "VerifySignature() should fail when signature is nil")

	// Re-sign with a new published timestamp.
	err = ri.ReSign(time.Now(), &keyPair.ed25519PrivKey, signature.SIGNATURE_TYPE_EDDSA_SHA512_ED25519)
	require.NoError(t, err)

	// Signature should now be valid again.
	valid, err = ri.VerifySignature()
	require.NoError(t, err)
	assert.True(t, valid, "signature should be valid after ReSign")

	// The RouterInfo should have both addresses.
	assert.Equal(t, 2, ri.RouterAddressCount())

	// Serialization should succeed.
	_, err = ri.Bytes()
	assert.NoError(t, err)
}

// TestReSignPreservesAddresses verifies that ReSign does not drop or reorder the
// address list.
func TestReSignPreservesAddresses(t *testing.T) {
	keyPair := generateTestKeyPair(t)
	routerIdentity := assembleTestRouterIdentity(t, keyPair)

	addr1, err := router_address.NewRouterAddress(3, time.Time{}, "NTCP2", map[string]string{"host": "1.2.3.4", "port": "9001"})
	require.NoError(t, err)
	addr2, err := router_address.NewRouterAddress(7, time.Time{}, "SSU2", map[string]string{"host": "1.2.3.4", "port": "9002"})
	require.NoError(t, err)

	ri, err := NewRouterInfo(
		routerIdentity,
		time.Now(),
		[]*router_address.RouterAddress{addr1},
		map[string]string{"caps": "LfR"},
		&keyPair.ed25519PrivKey,
		signature.SIGNATURE_TYPE_EDDSA_SHA512_ED25519,
	)
	require.NoError(t, err)
	require.NoError(t, ri.AddAddress(addr2))
	require.NoError(t, ri.ReSign(time.Now(), &keyPair.ed25519PrivKey, signature.SIGNATURE_TYPE_EDDSA_SHA512_ED25519))

	addrs := ri.RouterAddresses()
	require.Len(t, addrs, 2)

	style0, err := addrs[0].TransportStyle().Data()
	require.NoError(t, err)
	style1, err := addrs[1].TransportStyle().Data()
	require.NoError(t, err)
	assert.Equal(t, "NTCP2", style0)
	assert.Equal(t, "SSU2", style1)
}

// TestReSignRoundTrip verifies that a re-signed RouterInfo survives a full
// serialize → parse → verify cycle.
func TestReSignRoundTrip(t *testing.T) {
	keyPair := generateTestKeyPair(t)
	routerIdentity := assembleTestRouterIdentity(t, keyPair)

	addr, err := router_address.NewRouterAddress(3, time.Time{}, "NTCP2", map[string]string{"host": "10.0.0.1", "port": "9001"})
	require.NoError(t, err)

	ri, err := NewRouterInfo(
		routerIdentity,
		time.Now(),
		[]*router_address.RouterAddress{addr},
		map[string]string{"caps": "LfR"},
		&keyPair.ed25519PrivKey,
		signature.SIGNATURE_TYPE_EDDSA_SHA512_ED25519,
	)
	require.NoError(t, err)

	ssu2, err := router_address.NewRouterAddress(7, time.Time{}, "SSU2", map[string]string{"host": "10.0.0.1", "port": "9002"})
	require.NoError(t, err)
	require.NoError(t, ri.AddAddress(ssu2))
	require.NoError(t, ri.ReSign(time.Now(), &keyPair.ed25519PrivKey, signature.SIGNATURE_TYPE_EDDSA_SHA512_ED25519))

	wireBytes, err := ri.Bytes()
	require.NoError(t, err)

	parsed, remainder, err := ReadRouterInfo(wireBytes)
	require.NoError(t, err)
	assert.Empty(t, remainder)

	valid, err := parsed.VerifySignature()
	require.NoError(t, err)
	assert.True(t, valid, "signature should verify on parsed re-signed RouterInfo")
	assert.Equal(t, 2, parsed.RouterAddressCount())
}

// TestReSignNilKeyReturnsError ensures ReSign propagates the error from a nil key.
func TestReSignNilKeyReturnsError(t *testing.T) {
	ri, err := generateTestRouterInfo(t, time.Now())
	require.NoError(t, err)

	err = ri.ReSign(time.Now(), nil, signature.SIGNATURE_TYPE_EDDSA_SHA512_ED25519)
	assert.Error(t, err)
}
