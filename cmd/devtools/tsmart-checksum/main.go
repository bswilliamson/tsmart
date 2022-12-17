//go:build devtools

package main

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"strings"
)

func main() {
	net.LookupAddr("test")
	scanner := bufio.NewScanner(os.Stdin)
	var checksum byte
	for scanner.Scan() {
		line := scanner.Text()
		line = strings.ReplaceAll(line, ",", "")
		line = strings.ReplaceAll(line, "0x", "")
		vals := strings.Split(line, " ")
		for _, v := range vals {
			bytes, err := hex.DecodeString(v)
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
			if len(bytes) != 1 {
				fmt.Fprintf(os.Stderr, "value is larger than one byte: %s\n", v)
			}
			checksum ^= bytes[0]
		}
	}

	checksum ^= 0x55
	fmt.Printf("0x%s\n", hex.EncodeToString([]byte{checksum}))
}
