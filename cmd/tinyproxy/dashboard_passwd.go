package main

import (
	"fmt"
	"log"
	"os"

	"golang.org/x/crypto/bcrypt"
	"golang.org/x/term"
)

// runDashboardPasswd is an interactive bcrypt credential generator.
// It prompts for a username and password (hidden), then prints a
// username:hash line ready to paste into a credentials file.
func runDashboardPasswd() {
	fmt.Print("Username: ")
	var username string
	fmt.Scanln(&username)
	if username == "" {
		log.Fatal("username cannot be empty")
	}

	fmt.Print("Password: ")
	pw, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println()
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
	fmt.Printf("%s:%s\n", username, hash)
}
