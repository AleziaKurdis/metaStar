package main

import (
	"bufio"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/overte-org/overte-ice-server/internal/protocol"
)

type inspection struct {
	Line            int    `json:"line"`
	Sequence        uint32 `json:"sequence"`
	PacketType      byte   `json:"packet_type"`
	PacketName      string `json:"packet_name"`
	Version         byte   `json:"version"`
	ExpectedVersion *byte  `json:"expected_version,omitempty"`
	VersionMatches  *bool  `json:"version_matches,omitempty"`
	PayloadBytes    int    `json:"payload_bytes"`
}

func main() {
	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "Usage: ice-packet-inspect < datagrams.hex\n\n")
		fmt.Fprintln(flag.CommandLine.Output(), "Read one UDP payload per line as hexadecimal (for example, tshark's data.data field).")
		fmt.Fprintln(flag.CommandLine.Output(), "Blank lines and lines beginning with # are ignored. Results are JSON Lines.")
	}
	flag.Parse()
	if flag.NArg() != 0 {
		flag.Usage()
		os.Exit(2)
	}

	scanner := bufio.NewScanner(os.Stdin)
	scanner.Buffer(make([]byte, 4096), 1<<20)
	encoder := json.NewEncoder(os.Stdout)
	lineNumber := 0
	failed := false

	for scanner.Scan() {
		lineNumber++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		result, err := inspectLine(line, lineNumber)
		if err != nil {
			fmt.Fprintf(os.Stderr, "line %d: %v\n", lineNumber, err)
			failed = true
			continue
		}
		if err := encoder.Encode(result); err != nil {
			fmt.Fprintf(os.Stderr, "write result: %v\n", err)
			os.Exit(1)
		}
	}
	if err := scanner.Err(); err != nil {
		fmt.Fprintf(os.Stderr, "read input: %v\n", err)
		os.Exit(1)
	}
	if failed {
		os.Exit(1)
	}
}

func inspectLine(line string, lineNumber int) (inspection, error) {
	encoded := strings.TrimSpace(line)
	if len(encoded) >= 2 && strings.EqualFold(encoded[:2], "0x") {
		encoded = encoded[2:]
	}
	encoded = strings.NewReplacer(" ", "", "\t", "", ":", "", "-", "").Replace(encoded)
	if encoded == "" {
		return inspection{}, fmt.Errorf("empty hexadecimal datagram")
	}
	datagram, err := hex.DecodeString(encoded)
	if err != nil {
		return inspection{}, fmt.Errorf("invalid hexadecimal datagram: %w", err)
	}
	packet, err := protocol.DecodeDatagram(datagram)
	if err != nil {
		return inspection{}, fmt.Errorf("invalid Overte ICE UDT frame: %w", err)
	}

	result := inspection{
		Line:         lineNumber,
		Sequence:     packet.Sequence,
		PacketType:   packet.Type,
		PacketName:   packetName(packet.Type),
		Version:      packet.Version,
		PayloadBytes: len(packet.Payload),
	}
	if expected, ok := expectedVersion(packet.Type); ok {
		match := packet.Version == expected
		result.ExpectedVersion = &expected
		result.VersionMatches = &match
	}
	return result, nil
}

func packetName(packetType byte) string {
	switch packetType {
	case protocol.PacketICEServerPeerInformation:
		return "ICEServerPeerInformation"
	case protocol.PacketICEServerQuery:
		return "ICEServerQuery"
	case protocol.PacketICEServerHeartbeat:
		return "ICEServerHeartbeat"
	case protocol.PacketICEServerHeartbeatDenied:
		return "ICEServerHeartbeatDenied"
	case protocol.PacketICEServerHeartbeatACK:
		return "ICEServerHeartbeatACK"
	default:
		return "unknown"
	}
}

func expectedVersion(packetType byte) (byte, bool) {
	switch packetType {
	case protocol.PacketICEServerPeerInformation, protocol.PacketICEServerQuery,
		protocol.PacketICEServerHeartbeatDenied, protocol.PacketICEServerHeartbeatACK:
		return protocol.VersionICEStandard, true
	case protocol.PacketICEServerHeartbeat:
		return protocol.VersionICEHeartbeat, true
	default:
		return 0, false
	}
}
