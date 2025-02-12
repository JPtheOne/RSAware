// Debugging function to test reading files
package scratch

import (
	"log"
	"os"
)

func ReadFile() {
	bs, err := os.ReadFile("victim/simple.txt")
	if err != nil {
		log.Fatal(err)
	}
	log.Println(string(bs))
}
