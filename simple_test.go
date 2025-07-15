package main

import (
"fmt"
"github.com/go-i2p/common/data"
)

func main() {
fmt.Println("Testing I2P String bug claim...")

// Test case from audit: len(str) == 1
testStr := data.I2PString([]byte{0x00})
length, err := testStr.Length()
fmt.Printf("Length: %d, Error: %v\n", length, err)
fmt.Printf("Error type: %T\n", err)

// Check if this is ErrDataTooLong
if err == data.ErrDataTooLong {
fmt.Println("ErrDataTooLong triggered - would cause panic in Data()")
} else {
fmt.Println("ErrDataTooLong NOT triggered - no panic possible")
}
}
