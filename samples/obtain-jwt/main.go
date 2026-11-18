// Command obtain-jwt demonstrates a self-contained JWT workflow.
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
	"github.com/cloud-idaas/idaas-go-pam-client-sdk/samples/internal/jwtflow"
)

func main() {
	flag.Parse()
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	identifier := os.Getenv("PAM_CREDENTIAL_PROVIDER_IDENTIFIER")
	audience := os.Getenv("PAM_AUDIENCE")
	if identifier == "" || audience == "" {
		return errors.New("PAM_CREDENTIAL_PROVIDER_IDENTIFIER and PAM_AUDIENCE must be set")
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
	if err := jwtflow.Run(ctx, client, "obtain-jwt", identifier, audience); err != nil {
		return err
	}
	fmt.Println("Workflow completed and sample token revoked; credential values omitted")
	return nil
}
