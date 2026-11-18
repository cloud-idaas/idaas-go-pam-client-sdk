// Package jwtflow contains workflows shared by the runnable JWT examples.
package jwtflow

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	pam "github.com/cloud-idaas/idaas-go-pam-client-sdk"
)

// Run creates a token for a unique subject, demonstrates the selected workflow,
// and attempts single-token revocation on every exit after successful generation.
func Run(ctx context.Context, client *pam.Client, mode, identifier, audience string) (err error) {
	if mode != "generate-jwt" && mode != "obtain-jwt" && mode != "token-lifecycle" && mode != "consumer-lifecycle" {
		return errors.New("unknown JWT sample workflow")
	}
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		return errors.New("could not generate a unique sample subject")
	}
	subject := "go-pam-sample-" + hex.EncodeToString(random[:])
	// Only the run identifier is printed, so interrupted runs can be found and cleaned up.
	fmt.Println("Sample subject:", subject)
	expiration := int64(300)
	includeShort := mode == "obtain-jwt"
	generated, err := client.GenerateJWTAuthenticationToken(ctx, pam.GenerateJWTAuthenticationTokenRequest{
		CredentialProviderIdentifier: identifier, Subject: subject, Audiences: []string{audience},
		Expiration: &expiration, IncludeDerivedShortToken: &includeShort,
	})
	if err != nil {
		return err
	}
	defer func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if cleanupErr := client.RevokeAuthenticationToken(cleanupCtx, generated.JWTContent.JWTValue, nil); cleanupErr != nil {
			if err == nil {
				err = fmt.Errorf("sample cleanup failed; revoke the token for the printed subject: %w", cleanupErr)
			} else {
				err = fmt.Errorf("%w; cleanup also failed, revoke the token for the printed subject", err)
			}
		}
	}()
	if generated.ConsumerID == nil || *generated.ConsumerID != subject {
		return errors.New("generated consumer does not match this run's unique subject")
	}
	switch mode {
	case "obtain-jwt":
		if _, err := client.ObtainJWTAuthenticationToken(ctx, subject, generated.AuthenticationTokenID); err != nil {
			return err
		}
		if generated.JWTContent.DerivedShortToken == nil || *generated.JWTContent.DerivedShortToken == "" {
			return errors.New("provider did not return a derived short token")
		}
		if _, err := client.ObtainJWTAuthenticationTokenByDerivedShortToken(ctx, *generated.JWTContent.DerivedShortToken); err != nil {
			return err
		}
	case "token-lifecycle":
		if err := expectActive(ctx, client, generated.JWTContent.JWTValue, true); err != nil {
			return err
		}
		if err := client.RevokeAuthenticationToken(ctx, generated.JWTContent.JWTValue, nil); err != nil {
			return err
		}
		if err := expectActive(ctx, client, generated.JWTContent.JWTValue, false); err != nil {
			return err
		}
		if err := client.ReinstateAuthenticationToken(ctx, generated.JWTContent.JWTValue, nil); err != nil {
			return err
		}
		return expectActive(ctx, client, generated.JWTContent.JWTValue, true)
	case "consumer-lifecycle":
		if err := client.RevokeAuthenticationTokenByConsumer(ctx, subject, identifier); err != nil {
			return err
		}
		if err := expectActive(ctx, client, generated.JWTContent.JWTValue, false); err != nil {
			return err
		}
		if err := client.ReinstateAuthenticationTokenByConsumer(ctx, subject, identifier); err != nil {
			return err
		}
		return expectActive(ctx, client, generated.JWTContent.JWTValue, true)
	}
	return nil
}

func expectActive(ctx context.Context, client *pam.Client, token string, want bool) error {
	active, err := client.ValidateAuthenticationToken(ctx, token, nil)
	if err != nil {
		return err
	}
	if active != want {
		return fmt.Errorf("unexpected token state: active=%t, want %t", active, want)
	}
	return nil
}
