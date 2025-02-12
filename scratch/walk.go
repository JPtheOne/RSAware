/// Manual functions to enumerate files in a directory
package scratch

import (
	"flag"
	"log"
	"path/filepath"
	"os"
)

func EnumeratingFiles(path string, fi os.FileInfo, err error) error {
	if fi.IsDir() {
		return nil
	}
	
	log.Println(path)
	return nil
}

func Walk() {
	dir := flag.String("dir", "", "Directory to walk.")
	flag.Parse()

	if len(*dir) == 0 {
		log.Fatal("Please provide a -dir...")
	}

	err := filepath.Walk(*dir, EnumeratingFiles)
	if err != nil {
		log.Fatal(err)
	}
}
