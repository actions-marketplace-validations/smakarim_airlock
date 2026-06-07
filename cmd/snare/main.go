package main

import (
	"flag"
	"fmt"
	"os"
)

var version = "0.0.0-dev"

func main() {
	fs := flag.NewFlagSet("snare", flag.ExitOnError)
	showVersion := fs.Bool("version", false, "print version and exit")
	// Under flag.ExitOnError, Parse calls os.Exit on bad input, so the
	// returned error is always nil; the blank assignment silences the linter.
	_ = fs.Parse(os.Args[1:])

	if *showVersion {
		fmt.Println("snare", version)
		return
	}
	fmt.Fprintln(os.Stderr, "usage: snare audit [flags]")
	os.Exit(2)
}
