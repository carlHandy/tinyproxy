package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"golang.org/x/crypto/bcrypt"
	"golang.org/x/term"
)

// runDashboardPasswd is an interactive bcrypt credential generator.
// With --output <file> it writes the username:hash line directly to the file.
func runDashboardPasswd(args []string) {
	fs := flag.NewFlagSet("dashboard passwd", flag.ExitOnError)
	output := fs.String("output", "", "write credential line to this file instead of stdout")
	fs.Parse(args)

	fmt.Fprint(os.Stderr, "Username: ")
	var username string
	fmt.Scanln(&username)
	if username == "" {
		log.Fatal("username cannot be empty")
	}

	fmt.Fprint(os.Stderr, "Password: ")
	pw, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		log.Fatalf("failed to read password: %v", err)
	}
	if len(pw) == 0 {
		log.Fatal("password cannot be empty")
	}

	hash, err := bcrypt.GenerateFromPassword(pw, 12)
	if err != nil {
		log.Fatalf("failed to hash password: %v", err)
	}

	line := fmt.Sprintf("%s:%s\n", username, hash)

	if *output != "" {
		if err := os.WriteFile(*output, []byte(line), 0600); err != nil {
			log.Fatalf("failed to write credentials file: %v", err)
		}
		fmt.Fprintf(os.Stderr, "Credentials written to %s\n", *output)
		return
	}
	fmt.Print(line)
}
