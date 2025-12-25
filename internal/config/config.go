package config

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Mode indicates whether the process is running as a client or server.
type Mode int

const (
	Client Mode = iota
	Server
)

// Config holds runtime parameters for the tunnel.
type Config struct {
	Mode         Mode
	Local        string
	Remote       string
	Key          string
	RawMode      string
	CipherMode   string
	AuthMode     string
	DisableColor bool
	LogLevel     int
	Heartbeat    time.Duration
	MtuWarn      int
	ConfFile     string
}

// Parse parses CLI arguments and optionally loads a configuration file.
// Command-line arguments take precedence over configuration file values.
func Parse(args []string) (*Config, error) {
	cfg := &Config{
		RawMode:    "faketcp",
		CipherMode: "aes128cbc",
		AuthMode:   "hmac_sha1",
		LogLevel:   4,
		Heartbeat:  10 * time.Second,
		MtuWarn:    1375,
	}

	confPath := locateConfFile(args)
	if confPath != "" {
		cfg.ConfFile = confPath
		fileArgs, err := LoadFile(confPath)
		if err != nil {
			return nil, err
		}
		args = mergeArgs(fileArgs, args)
	}

	fs := flag.NewFlagSet("udp2raw", flag.ContinueOnError)
	fs.StringVar(&cfg.Local, "l", "", "local listen address ip:port")
	fs.StringVar(&cfg.Local, "local", "", "local listen address ip:port")
	fs.StringVar(&cfg.Remote, "r", "", "remote address ip:port")
	fs.StringVar(&cfg.Remote, "remote", "", "remote address ip:port")
	client := fs.Bool("c", false, "run as client")
	server := fs.Bool("s", false, "run as server")
	fs.StringVar(&cfg.Key, "k", "secret key", "pre-shared key")
	fs.StringVar(&cfg.Key, "key", "secret key", "pre-shared key")
	fs.StringVar(&cfg.RawMode, "raw-mode", cfg.RawMode, "faketcp|udp|icmp|easy-faketcp")
	fs.StringVar(&cfg.CipherMode, "cipher-mode", cfg.CipherMode, "aes128cbc|aes128cfb|xor|none")
	fs.StringVar(&cfg.AuthMode, "auth-mode", cfg.AuthMode, "hmac_sha1|md5|crc32|simple|none")
	fs.BoolVar(&cfg.DisableColor, "disable-color", false, "disable log color")
	fs.IntVar(&cfg.LogLevel, "log-level", cfg.LogLevel, "0-6 log level")
	hb := fs.Int("hb-len", 0, "heartbeat payload length (ignored, kept for compatibility)")
	fs.IntVar(&cfg.MtuWarn, "mtu-warn", cfg.MtuWarn, "mtu warning threshold")
	fs.StringVar(&cfg.ConfFile, "conf-file", cfg.ConfFile, "configuration file path")

	// Suppress default output; caller controls stderr.
	fs.SetOutput(new(strings.Builder))

	if err := fs.Parse(args); err != nil {
		return nil, err
	}

	_ = hb // kept only for compatibility

	if *client == *server {
		return nil, errors.New("choose exactly one of -c or -s")
	}
	if *client {
		cfg.Mode = Client
	} else {
		cfg.Mode = Server
	}

	if cfg.Local == "" || cfg.Remote == "" {
		return nil, errors.New("both -l and -r are required")
	}

	if _, err := net.ResolveUDPAddr("udp", cfg.Local); err != nil {
		return nil, fmt.Errorf("invalid local address: %w", err)
	}
	if _, err := net.ResolveUDPAddr("udp", cfg.Remote); err != nil {
		return nil, fmt.Errorf("invalid remote address: %w", err)
	}

	cfg.RawMode = strings.ToLower(cfg.RawMode)
	cfg.CipherMode = strings.ToLower(cfg.CipherMode)
	cfg.AuthMode = strings.ToLower(cfg.AuthMode)

	return cfg, nil
}

// LoadFile parses a configuration file that uses the legacy key-value syntax.
func LoadFile(path string) ([]string, error) {
	f, err := os.Open(filepath.Clean(path))
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var args []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		args = append(args, fields...)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return args, nil
}

// mergeArgs ensures CLI args override config values.
func mergeArgs(fileArgs, cliArgs []string) []string {
	// append cliArgs at the end to let them win during parsing
	merged := make([]string, 0, len(fileArgs)+len(cliArgs))
	merged = append(merged, fileArgs...)
	merged = append(merged, cliArgs...)
	return merged
}

func locateConfFile(args []string) string {
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if strings.HasPrefix(arg, "--conf-file=") {
			return strings.TrimPrefix(arg, "--conf-file=")
		}
		if arg == "--conf-file" && i+1 < len(args) {
			return args[i+1]
		}
	}
	return ""
}
