// Command obtain-sts demonstrates a PAM operation using external Core configuration.
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
	role := os.Getenv("PAM_ROLE_EXTERNAL_ID")
	if role == "" {
		return errors.New("PAM_ROLE_EXTERNAL_ID must be set")
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
	result, err := client.ObtainAccessCredential(ctx, role)
	if err != nil {
		return err
	}
	// Validate required fields and expiration before using these credentials.
	fmt.Printf("STS responses: Alibaba Cloud=%t AWS=%t Tencent Cloud=%t\n",
		result.AlibabaCloudSTSToken != nil, result.AWSSTSToken != nil, result.TencentCloudSTSToken != nil)
	return nil
}
