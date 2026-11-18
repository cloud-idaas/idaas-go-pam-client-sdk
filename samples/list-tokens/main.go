// Command list-tokens demonstrates a PAM operation using external Core configuration.
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
	identifier := os.Getenv("PAM_CREDENTIAL_PROVIDER_IDENTIFIER")
	if identifier == "" {
		return errors.New("PAM_CREDENTIAL_PROVIDER_IDENTIFIER must be set")
	}
	consumer := os.Getenv("PAM_CONSUMER_ID")
	if consumer == "" {
		return errors.New("PAM_CONSUMER_ID must be set")
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
	input := pam.ListAuthenticationTokensRequest{ConsumerID: consumer, CredentialProviderIdentifier: identifier}
	total := 0
	for {
		page, err := client.ListAuthenticationTokens(ctx, input)
		if err != nil {
			return err
		}
		total += len(page.Entities)
		if page.NextToken == "" {
			break
		}
		if page.NextToken == input.NextToken {
			return errors.New("server repeated the pagination cursor")
		}
		input.NextToken = page.NextToken
	}
	fmt.Printf("Tokens listed: %d; token metadata omitted\n", total)
	return nil
}
