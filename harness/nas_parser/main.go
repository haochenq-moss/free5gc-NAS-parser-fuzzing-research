package main

import (
	"io"
	"os"

	"github.com/free5gc/nas/message"
)

const maxInputBytes = 4096

func main() {
	if len(os.Args) != 3 {
		os.Exit(2)
	}

	inputFile, err := os.Open(os.Args[2])
	if err != nil {
		os.Exit(2)
	}
	defer inputFile.Close()

	input, err := io.ReadAll(io.LimitReader(inputFile, maxInputBytes+1))
	if err != nil || len(input) > maxInputBytes {
		return
	}

	switch os.Args[1] {
	case "gmm":
		_, _ = message.ParseGMM(input)
	case "gsm":
		_, _ = message.ParseGSM(input)
	default:
		os.Exit(2)
	}
}
