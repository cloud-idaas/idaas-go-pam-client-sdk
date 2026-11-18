// Command get-api-key demonstrates a PAM operation using external Core configuration.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/cloud-idaas/idaas-go-core-sdk/factory"
	pam "github.com/cloud-idaas/idaas-go-pam-client-sdk"
)

func main() {
	flag.Parse()
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	identifier := os.Getenv("PAM_CREDENTIAL_IDENTIFIER")
	if identifier == "" {
		return errors.New("PAM_CREDENTIAL_IDENTIFIER must be set")
	}
	if err := factory.Init(); err != nil {
		return errors.New("Core initialization failed; check your external configuration and secret environment variable")
	}
	client, err := pam.NewDefaultClient()
	if err != nil {
		return err
	}
	defer func() { _ = client.Close() }()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	key, err := client.GetAPIKey(ctx, identifier)
	if err != nil {
		return err
	}
	fmt.Printf("API key present: %t\n", key != nil)
	return nil
}
