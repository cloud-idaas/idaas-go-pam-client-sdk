package pam

import (
	"encoding/json"
	"net/url"
	"strconv"
)

func generationBody(input GenerateJWTAuthenticationTokenRequest) (map[string]interface{}, error) {
	if err := required(input.CredentialProviderIdentifier, "credentialProviderIdentifier"); err != nil {
		return nil, err
	}
	if err := required(input.Subject, "subject"); err != nil {
		return nil, err
	}
	if len(input.Audiences) == 0 {
		return nil, configError("audiences must contain at least one nonempty string")
	}
	for _, audience := range input.Audiences {
		if err := required(audience, "audience"); err != nil {
			return nil, err
		}
	}
	body := map[string]interface{}{
		"credentialProviderIdentifier": input.CredentialProviderIdentifier,
		"subject":                      input.Subject,
		"audiences":                    input.Audiences,
	}
	if input.Issuer != nil {
		if err := required(*input.Issuer, "issuer"); err != nil {
			return nil, err
		}
		body["issuer"] = *input.Issuer
	}
	if input.Expiration != nil {
		if *input.Expiration < 1 || *input.Expiration > 315360000 {
			return nil, configError("expiration must be between 1 and 315360000 seconds")
		}
		body["expiration"] = *input.Expiration
	}
	if input.IncludeDerivedShortToken != nil {
		body["includeDerivedShortToken"] = *input.IncludeDerivedShortToken
	}
	if input.CustomClaims != nil {
		claims, err := json.Marshal(input.CustomClaims)
		if err != nil || len(claims) > 16384 {
			return nil, configError("customClaims must encode to at most 16384 UTF-8 JSON bytes")
		}
		// Freeze custom MarshalJSON results before requesting credentials.
		body["customClaims"] = json.RawMessage(claims)
	}
	return body, nil
}

func tokenBody(token string, options *TokenOptions) (map[string]interface{}, error) {
	if err := required(token, "token"); err != nil {
		return nil, err
	}
	body := map[string]interface{}{"token": token}
	if options != nil && options.TokenTypeHint != nil {
		if err := required(*options.TokenTypeHint, "token_type_hint"); err != nil {
			return nil, err
		}
		body["token_type_hint"] = *options.TokenTypeHint
	}
	return body, nil
}

func validBearer(token string) bool {
	if token == "" {
		return false
	}
	for _, character := range token {
		if character <= ' ' || character >= 0x7f {
			return false
		}
	}
	return true
}

func listQuery(input ListAuthenticationTokensRequest) (url.Values, error) {
	if err := required(input.ConsumerID, "consumerId"); err != nil {
		return nil, err
	}
	if err := required(input.CredentialProviderIdentifier, "credentialProviderIdentifier"); err != nil {
		return nil, err
	}
	query := url.Values{"consumerId": {input.ConsumerID}, "credentialProviderIdentifier": {input.CredentialProviderIdentifier}}
	if input.NextToken != "" {
		query.Set("nextToken", input.NextToken)
	}
	if input.MaxResults != nil {
		if *input.MaxResults <= 0 {
			return nil, configError("maxResults must be a positive integer")
		}
		query.Set("maxResults", strconv.FormatInt(*input.MaxResults, 10))
	}
	for name, value := range map[string]*bool{"revoked": input.Revoked, "expired": input.Expired} {
		if value != nil {
			query.Set(name, strconv.FormatBool(*value))
		}
	}
	return query, nil
}
