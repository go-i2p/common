package router_info

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/samber/oops"
)

func consolidateNetDb(sourcePath string, destPath string) error {
	// Create destination directory if it doesn't exist
	if err := os.MkdirAll(destPath, 0o755); err != nil {
		return oops.Errorf("failed to create destination directory: %v", err)
	}

	// Walk through all subdirectories
	return filepath.Walk(sourcePath, func(path string, info os.FileInfo, err error) error {
		fmt.Println("Visiting:", path)
		if err != nil {
			return oops.Errorf("error accessing path %q: %v", path, err)
		}

		// Skip if it's a directory
		if info.IsDir() {
			fmt.Println("Skipping directory:", path)
			return nil
		}

		fmt.Println("Processing file:", info.Name())

		// Check if this is a routerInfo file
		if strings.HasPrefix(info.Name(), "routerInfo-") && strings.HasSuffix(info.Name(), ".dat") {
			fmt.Println("Found routerInfo file:", info.Name())
			// Create source file path
			srcFile := path

			// Create destination file path
			dstFile := filepath.Join(destPath, info.Name())

			// Copy the file
			if err := copyFile(srcFile, dstFile); err != nil {
				return oops.Errorf("failed to copy %s: %v", info.Name(), err)
			}
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
	// Common paths for I2P and I2Pd netDb
	i2pPath := filepath.Join(os.Getenv("HOME"), ".i2p/netDb")
	i2pdPath := filepath.Join(os.Getenv("HOME"), ".i2pd/netDb")

	// Create the temp directory
	if err := os.MkdirAll(tempDir, 0o755); err != nil {
		return oops.Errorf("failed to create temp directory: %v", err)
	}

	// Try to consolidate I2P netDb
	if _, err := os.Stat(i2pPath); err == nil {
		if err := consolidateNetDb(i2pPath, tempDir); err != nil {
			fmt.Printf("Warning: Error processing I2P netDb: %v\n", err)
		}
	}

	// Try to consolidate I2Pd netDb
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
	// Get system's temp directory in a platform-independent way
	baseDir, _ := os.Getwd() //os.TempDir()
	baseDir = filepath.Join(baseDir, "temp")

	// Create unique directory name with timestamp
	timestamp := time.Now().Unix()
	dirName := fmt.Sprintf("go-i2p-testfiles-%d", timestamp)

	// Join paths in a platform-independent way
	tempDir := filepath.Join(baseDir, dirName)

	// Create the directory with appropriate permissions
	err := os.MkdirAll(tempDir, 0o755)
	if err != nil {
		return "", oops.Errorf("failed to create temporary directory: %v", err)
	}

	return tempDir, nil
}

func Test10K(t *testing.T) {
	if err := checkNetDbDirectoriesExist(t); err != nil {
		return // Test was skipped
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

// checkNetDbDirectoriesExist verifies that at least one netDb directory exists.
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

// setupTestDirectories creates temporary directories and consolidates netDb data.
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

// processAllRouterInfoFiles reads, parses, and writes router info files from temp to target directory.
func processAllRouterInfoFiles(t *testing.T, tempDir, targetDir string) error {
	files, err := os.ReadDir(tempDir)
	if err != nil {
		return fmt.Errorf("failed to read temp directory: %v", err)
	}

	for d, file := range files {
		if shouldProcessFile(file) {
			if err := processRouterInfoFile(t, tempDir, targetDir, file, d); err != nil {
				t.Logf("Failed to process file %s: %v", file.Name(), err)
				// continue
				return err
			}
		}
	}

	return nil
}

// shouldProcessFile determines if a file should be processed as a router info file.
func shouldProcessFile(file os.DirEntry) bool {
	return !file.IsDir() && strings.HasPrefix(file.Name(), "routerInfo-")
}

// processRouterInfoFile handles the complete processing of a single router info file.
func processRouterInfoFile(t *testing.T, tempDir, targetDir string, file os.DirEntry, fileIndex int) error {
	fmt.Println("RI LOAD: ", fileIndex, file.Name())

	data, err := readRouterInfoFile(tempDir, file.Name())
	if err != nil {
		return fmt.Errorf("failed to read file: %v", err)
	}

	routerInfo, err := parseRouterInfoData(data)
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

// readRouterInfoFile reads router info data from a file in the specified directory.
func readRouterInfoFile(directory, filename string) ([]byte, error) {
	return os.ReadFile(filepath.Join(directory, filename))
}

// parseRouterInfoData parses router info from raw byte data.
func parseRouterInfoData(data []byte) (RouterInfo, error) {
	routerInfo, _, err := ReadRouterInfo(data)
	if err != nil {
		return RouterInfo{}, err
	}
	return routerInfo, nil
}

// writeRouterInfoFile serializes and writes router info to a file in the target directory.
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

// cleanupTestDirectories removes temporary directories and logs any cleanup errors.
func cleanupTestDirectories(t *testing.T, tempDir, targetDir string) {
	cleanupSingleDirectory(t, tempDir, "temp")
	cleanupSingleDirectory(t, targetDir, "target")
}

// cleanupSingleDirectory removes a single directory and logs the result.
func cleanupSingleDirectory(t *testing.T, dir, dirType string) {
	if err := cleanupTempDir(dir); err != nil {
		log.WithError(err).Error("Failed to cleanup " + dirType + " directory")
		t.Errorf("Failed to cleanup %s directory: %v", dirType, err)
	} else {
		log.Debug("Successfully cleaned up " + dirType + " directory")
	}
}
