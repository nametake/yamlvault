package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"os"

	"github.com/nametake/yamlvault"
)

func main() {
	project := flag.String("project", "", "The Google Cloud Platform project ID. required.")
	location := flag.String("location", "", "The Google Cloud Platform location. required.")
	keyring := flag.String("keyring", "", "The Google Cloud Platform keyring. required.")
	keyname := flag.String("keyname", "", "The Google Cloud Platform keyname. required.")

	cmd := flag.String("cmd", "", "cmd is required. cmd is encrypt or decrypt")

	plain := flag.String("plain", "", "Plain YAML file path. required.")
	cihper := flag.String("cihper", "", "Cihper YAML file path. required.")

	flag.Parse()
	for _, f := range []string{"project", "location", "keyring", "keyname", "cmd", "plain", "cihper"} {
		if flag.Lookup(f).Value.String() == "" {
			log.Fatalf("The %s flag is required.", f)
		}
	}

	ctx := context.Background()

	s, err := yamlvault.NewKMS(ctx, *project, *location, *keyring, *keyname)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	plainFile, err := os.OpenFile(*plain, os.O_RDWR|os.O_CREATE, 0666)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	defer plainFile.Close()

	cihperFile, err := os.OpenFile(*cihper, os.O_RDWR|os.O_CREATE, 0666)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	defer cihperFile.Close()

	switch *cmd {
	case "encrypt":
		r, err := s.Encrypt(plainFile)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		if _, err := io.Copy(cihperFile, r); err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
	case "decrypt":
		r, err := s.Decrypt(cihperFile)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		if _, err := io.Copy(plainFile, r); err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
	default:
		fmt.Println("The cmd flog is encrypt or decrypt")
	}

}
