package scratch

import (
	"bytes"
	"fmt"
)

func pad(bs []byte, blksz int) []byte {
	// default to block size
	count := blksz
	// if we have leftover bytes
	if len(bs) % blksz != 0 {
		// difference between blocksize and leftover bytes
		count = blksz  - (len(bs) % blksz)
	}
	// create padding buffer
	padding := bytes.Repeat([]byte{byte(count)}, count)
	// append padding to plaintext
	bs = append(bs, padding...)
	// return bs
	return bs
}

func Padder() {
	// a quick test
	bs := []byte{0x00,0x11,0x22,0x33,0x44,0x55}
	bs = pad(bs, 16)
	fmt.Printf("%x\n", bs)
}