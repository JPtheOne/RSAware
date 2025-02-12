package util

import (
	"crypto/sha256"
	"flag"
	"log"
	"os"
	"path/filepath"
	"github.com/otiai10/copy"
)

func RestoreandVerify() { //DEBUGGING FUNCTION
	restore := flag.Bool("restore", false, "restore victim directory from _victim") //Restore the whole victim folder
	verify := flag.Bool("verify", false, "verify files in victim directory") //Verifies restored files

	flag.Parse()

	if !*restore && !*verify || *restore && *verify {
		log.Fatal("Requires one of -verify or -restore.")
	}

	if *restore {
		err := os.RemoveAll("victim")
		if err != nil {
			log.Fatal(err)
		}

		err = copy.Copy("_victim", "victim")
		if err != nil {
			log.Fatal(err)
		}
	} else if *verify {
		err := filepath.Walk("_victim", OnVisit)
		if err != nil {
			log.Fatal(err)
		}
	}
}

func OnVisit(path string, fi os.FileInfo, err error) error { //Hash checker, seeks changes in files
	if fi.IsDir() {
		return nil
	}

	// Read original.
	bsOrig, err := os.ReadFile(path)
	if err != nil {
		log.Println("Error reading", path)
		log.Println(err)
		return nil
	}

	hashOrig := sha256.Sum256(bsOrig)

	// Read copy.
	bsCopy, err := os.ReadFile(path[1:]) // Remove underscore to get victim counterpart
	if err != nil {
		log.Println("Error reading", path[1:])
		log.Println(err)
		return nil
	}

	hashCopy := sha256.Sum256(bsCopy)

	// Report mismatches.
	if hashOrig != hashCopy {
		log.Println("Mismatch for", path)
	}

	return nil
}
