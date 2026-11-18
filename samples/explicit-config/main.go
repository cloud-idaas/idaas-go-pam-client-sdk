// Command explicit-config demonstrates explicit PAM construction and error observation.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"time"

	coreconfig "github.com/cloud-idaas/idaas-go-core-sdk/config"
	coreerrors "github.com/cloud-idaas/idaas-go-core-sdk/errors"
	"github.com/cloud-idaas/idaas-go-core-sdk/factory"
	pam "github.com/cloud-idaas/idaas-go-pam-client-sdk"
)

func main() {
	flag.Parse()
	if err := run(); err != nil {
		var sdkErr coreerrors.IDaaSError
		switch {
		case errors.Is(err, context.Canceled):
			fmt.Fprintln(os.Stderr, "Operation canceled")
		case errors.Is(err, context.DeadlineExceeded):
			fmt.Fprintln(os.Stderr, "Operation deadline exceeded")
		case errors.Is(err, pam.ErrClosed):
			fmt.Fprintln(os.Stderr, "PAM client is closed")
		case errors.As(err, &sdkErr):
			fmt.Fprintf(os.Stderr, "SDK error: code=%s requestID=%s\n", sdkErr.ErrorCode(), sdkErr.RequestId())
		default:
			fmt.Fprintln(os.Stderr, err)
		}
		os.Exit(1)
	}
}

func run() error {
	identifier := os.Getenv("PAM_CREDENTIAL_IDENTIFIER")
	if identifier == "" {
		return errors.New("PAM_CREDENTIAL_IDENTIFIER must be set")
	}
	cfg, err := coreconfig.NewConfigReader().LoadWithPriority("")
	if err != nil {
		return errors.New("could not load external Core configuration")
	}
	if err := factory.InitWithConfig(cfg); err != nil {
		return errors.New("Core initialization failed; check your external configuration and secret environment variable")
	}
	provider, err := factory.GetIDaaSCredentialProviderByScope(pam.Scope)
	if err != nil {
		return errors.New("could not resolve the Core PAM credential provider")
	}
	// The host creates the provider. All required PAM settings are explicit;
	// this PAM constructor does not need to resolve defaults from the Core factory.
	client, err := pam.NewClient(pam.Config{
		DeveloperAPIEndpoint: cfg.DeveloperApiEndpoint,
		IDaaSInstanceID:      cfg.InstanceId,
		CredentialProvider:   provider,
		HTTPConfiguration:    cfg.HttpConfiguration,
	})
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
