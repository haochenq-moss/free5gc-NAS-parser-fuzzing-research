package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"

	"github.com/free5gc/nas/message"
)

type seed struct {
	Name     string `json:"name"`
	Protocol string `json:"protocol"`
	Category string `json:"category"`
	Hex      string `json:"hex"`
}

type result struct {
	Name     string `json:"name"`
	Protocol string `json:"protocol"`
	Category string `json:"category"`
	Length   int    `json:"length_bytes"`
	Parses   bool   `json:"parses"`
	Error    string `json:"error,omitempty"`
}

func main() {
	if len(os.Args) < 2 || len(os.Args) > 3 {
		fmt.Fprintln(os.Stderr, "usage: validate_nas_seed_suite <seeds.json> [results.json]")
		os.Exit(2)
	}
	data, err := os.ReadFile(os.Args[1])
	if err != nil {
		fatal(err)
	}
	var seeds []seed
	if err := json.Unmarshal(data, &seeds); err != nil {
		fatal(err)
	}
	results := make([]result, 0, len(seeds))
	for _, item := range seeds {
		pdu, err := hex.DecodeString(item.Hex)
		if err != nil {
			fatal(fmt.Errorf("%s: invalid hex: %w", item.Name, err))
		}
		var parseErr error
		switch item.Protocol {
		case "GMM":
			_, parseErr = message.ParseGMM(pdu)
		case "GSM":
			_, parseErr = message.ParseGSM(pdu)
		default:
			fatal(fmt.Errorf("%s: unsupported protocol %q", item.Name, item.Protocol))
		}
		entry := result{Name: item.Name, Protocol: item.Protocol, Category: item.Category, Length: len(pdu), Parses: parseErr == nil}
		if parseErr != nil {
			entry.Error = parseErr.Error()
		}
		results = append(results, entry)
	}
	output, err := json.MarshalIndent(results, "", "  ")
	if err != nil {
		fatal(err)
	}
	if len(os.Args) == 3 {
		if err := os.WriteFile(os.Args[2], append(output, '\n'), 0o644); err != nil {
			fatal(err)
		}
	}
	fmt.Println(string(output))
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}
