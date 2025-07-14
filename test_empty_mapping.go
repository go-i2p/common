package main

import (
"fmt"
"github.com/go-i2p/common/data"
)

func main() {
// Test empty mapping
emptyMap := make(map[string]string)
mapping, err := data.GoMapToMapping(emptyMap)
if err != nil {
fmt.Printf("Error creating empty mapping: %v\n", err)
return
}
fmt.Printf("Empty mapping data: %v\n", mapping.Data())
}
