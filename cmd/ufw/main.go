package main

import (
	"fmt"
	"os"
	"ufw/internal/backend"
	"ufw/internal/config"
	"ufw/internal/parser"
	"ufw/internal/rule"
	"ufw/internal/util"
)

const version = "0.1.0-windows"

func main() {
	if len(os.Args) > 1 && (os.Args[1] == "--version" || os.Args[1] == "-v") {
		fmt.Printf("ufw (Windows) %s\n", version)
		return
	}

	cmd, err := parser.Parse(os.Args[1:])
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: %v\n", err)
		os.Exit(1)
	}

	if cmd.Type == parser.CmdHelp {
		printUsage()
		return
	}

	// Windows Defender Firewall requires Administrator elevation to view and edit rules
	if !util.IsAdmin() {
		fmt.Fprintln(os.Stderr, "ERROR: You must be running as Administrator to run this command")
		os.Exit(1)
	}

	cfg, err := config.Load()
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: Could not load configuration: %v\n", err)
		os.Exit(1)
	}

	var be backend.Backend = backend.New()

	switch cmd.Type {
	case parser.CmdStatus:
		handleStatus(cmd.StatusMode, cfg, be)
	case parser.CmdAllow, parser.CmdDeny:
		handleAddRule(cmd.Rule, cfg, be)
	}
}

func handleStatus(mode parser.StatusMode, cfg *config.Config, be backend.Backend) {
	status, err := be.GetStatus()
	if err != nil {
		fmt.Fprintf(os.Stderr, "WARN: Could not query firewall state: %v\n", err)
	}

	if status != nil && !status.Active {
		fmt.Println("Status: inactive")
		return
	}

	fmt.Println("Status: active")

	if mode == parser.StatusVerbose && status != nil {
		fmt.Printf("Logging: %s\n", status.Logging)
		fmt.Printf("Default: %s, %s, disabled (routed)\n", status.DefaultInbound, status.DefaultOutbound)
		fmt.Println("New profiles: skip")
	}

	if len(cfg.Rules) == 0 {
		return
	}

	fmt.Println()

	isNumbered := mode == parser.StatusNumbered

	if isNumbered {
		fmt.Printf("%-5s%-27s%-12s%s\n", "", "To", "Action", "From")
		fmt.Printf("%-5s%-27s%-12s%s\n", "", "--", "------", "----")
		for _, r := range cfg.Rules {
			numPrefix := fmt.Sprintf("[%2d]", r.ID)
			fmt.Printf("%-5s%-27s%-12s%s\n", numPrefix, r.ToDisplay(), r.ActionDisplay(true), r.FromDisplay())
		}
	} else {
		fmt.Printf("%-27s%-12s%s\n", "To", "Action", "From")
		fmt.Printf("%-27s%-12s%s\n", "--", "------", "----")
		for _, r := range cfg.Rules {
			fmt.Printf("%-27s%-12s%s\n", r.ToDisplay(), r.ActionDisplay(false), r.FromDisplay())
		}
	}
}

func handleAddRule(r *rule.Rule, cfg *config.Config, be backend.Backend) {
	if dup := cfg.FindDuplicate(r); dup != nil {
		fmt.Println("Skipping adding existing rule")
		return
	}

	r.ID = cfg.NextID()

	if err := be.ApplyRule(r); err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: %v\n", err)
		os.Exit(1)
	}

	if err := cfg.AddRule(r); err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: Could not persist rule: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("Rule added")
}

func printUsage() {
	fmt.Println("Usage: ufw [--version] <command> [arguments...]")
	fmt.Println()
	fmt.Println("Commands:")
	fmt.Println("  status [numbered|verbose]    Show firewall status and rules")
	fmt.Println("  allow <rule-spec>            Add an allow rule")
	fmt.Println("  deny <rule-spec>             Add a deny (block) rule")
	fmt.Println()
	fmt.Println("Rule Specifications:")
	fmt.Println("  ufw allow <port>[/<protocol>]")
	fmt.Println("      e.g. ufw allow 51312")
	fmt.Println("      e.g. ufw allow 51312/udp")
	fmt.Println("      e.g. ufw allow 51312:51314/tcp")
	fmt.Println("      e.g. ufw allow ssh")
	fmt.Println("      e.g. ufw allow deluge")
	fmt.Println("  ufw allow from <ip-or-cidr>")
	fmt.Println("      e.g. ufw allow from 192.168.0.0/24")
	fmt.Println("  ufw allow from <ip-or-cidr> to any port <port> [proto <protocol>]")
	fmt.Println("      e.g. ufw allow from 192.168.0.0/24 to any port 22 proto tcp")
	fmt.Println("  ufw deny <rule-spec>")
	fmt.Println("      e.g. ufw deny 8080/tcp")
	fmt.Println("      e.g. ufw deny from 199.115.117.99")
}
