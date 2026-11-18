package pam

// GenerateJWTAuthenticationTokenRequest represents JWT generation parameters.
type GenerateJWTAuthenticationTokenRequest struct {
	// CredentialProviderIdentifier identifies a provider supporting JWT generation.
	// It is required and must be nonblank; use the configured identifier, not its ID.
	CredentialProviderIdentifier string
	// Subject identifies the subject for the generated token.
	// It is required and must be nonblank.
	Subject string
	// Audiences contains at least one nonblank permitted audience.
	Audiences []string
	// Issuer overrides the issuer when non-nil; a supplied value must be nonblank.
	Issuer *string
	// CustomClaims is omitted when nil; an empty map sends an empty object.
	// Its UTF-8 JSON encoding must not exceed 16,384 bytes.
	CustomClaims map[string]any
	// Expiration is the token lifetime in seconds, from 1 to 315,360,000.
	// Nil leaves the lifetime to the service.
	Expiration *int64
	// IncludeDerivedShortToken requests a derived short token when true.
	// Nil omits the option; a non-nil false value is sent explicitly.
	IncludeDerivedShortToken *bool
}

// ListAuthenticationTokensRequest represents token list filters and pagination.
type ListAuthenticationTokensRequest struct {
	// ConsumerID identifies the consumer whose tokens are listed.
	// It is required and must be nonblank.
	ConsumerID string
	// CredentialProviderIdentifier scopes the query to a credential provider.
	// It is required and must be a nonblank configured identifier, not its ID.
	CredentialProviderIdentifier string
	// NextToken is the opaque cursor from the previous response; empty starts a query.
	NextToken string
	// MaxResults is an optional positive page-size limit.
	MaxResults *int64
	// Revoked filters revocation state when non-nil, including an explicit false.
	Revoked *bool
	// Expired filters expiration state when non-nil, including an explicit false.
	Expired *bool
}

// TokenOptions represents optional parameters for ValidateAuthenticationToken,
// RevokeAuthenticationToken, and ReinstateAuthenticationToken.
type TokenOptions struct {
	// TokenTypeHint helps the service identify the supplied token's type.
	// Its accepted values are defined by the service; PAM sends it as token_type_hint.
	// Nil omits the hint; a supplied value must be nonblank.
	TokenTypeHint *string
}

// JWTContent represents a JWT and its optional derived short token.
type JWTContent struct {
	// JWTValue contains the JWT and must be kept confidential.
	JWTValue string `json:"jwtValue"`
	// DerivedShortToken is an optional confidential token for JWT exchange.
	DerivedShortToken *string `json:"derivedShortToken,omitempty"`
}

// JWTTokenResponse represents the result of JWT generation.
type JWTTokenResponse struct {
	// AuthenticationTokenID identifies the generated authentication token.
	AuthenticationTokenID string `json:"authenticationTokenId"`
	// ConsumerType is the optional service-defined consumer type.
	ConsumerType *string `json:"consumerType,omitempty"`
	// ConsumerID is the optional consumer identifier returned by the service.
	ConsumerID *string `json:"consumerId,omitempty"`
	// JWTContent contains confidential token values.
	JWTContent JWTContent `json:"jwtContent"`
}

// AuthenticationToken contains optional metadata; nil pointers mean absent fields.
// All timestamps in this type use Unix milliseconds.
type AuthenticationToken struct {
	// InstanceID identifies the instance when supplied.
	InstanceID *string `json:"instanceId,omitempty"`
	// AuthenticationTokenID identifies the token when supplied.
	AuthenticationTokenID *string `json:"authenticationTokenId,omitempty"`
	// AuthenticationTokenType is the service-defined token type.
	AuthenticationTokenType *string `json:"authenticationTokenType,omitempty"`
	// CredentialProviderID identifies the issuing credential provider.
	// Use CredentialProviderIdentifier for requests that require a configured identifier.
	CredentialProviderID *string `json:"credentialProviderId,omitempty"`
	// CreatorType is the service-defined creator type.
	CreatorType *string `json:"creatorType,omitempty"`
	// CreatorID identifies the creator.
	CreatorID *string `json:"creatorId,omitempty"`
	// ConsumerType is the service-defined consumer type.
	ConsumerType *string `json:"consumerType,omitempty"`
	// ConsumerID identifies the consumer.
	ConsumerID *string `json:"consumerId,omitempty"`
	// Revoked preserves an optional revocation flag, including false.
	Revoked *bool `json:"revoked,omitempty"`
	// CreateTime is the creation timestamp in Unix milliseconds.
	CreateTime *int64 `json:"createTime,omitempty"`
	// UpdateTime is the last update timestamp in Unix milliseconds.
	UpdateTime *int64 `json:"updateTime,omitempty"`
	// ExpirationTime is the expiration timestamp in Unix milliseconds.
	ExpirationTime *int64 `json:"expirationTime,omitempty"`
}

// AuthenticationTokenPage contains token metadata and pagination information.
type AuthenticationTokenPage struct {
	// Entities contains token metadata. Client results always use a non-nil slice.
	Entities []AuthenticationToken `json:"entities"`
	// TotalCount is the optional nonnegative total count reported by the service.
	TotalCount *int64 `json:"totalCount,omitempty"`
	// MaxResults is the optional nonnegative page-size value reported by the service.
	MaxResults *int64 `json:"maxResults,omitempty"`
	// NextToken is the opaque pagination cursor; empty means no further page.
	NextToken string `json:"nextToken,omitempty"`
}

// CloudAccountRoleAccessCredential holds cloud STS fields. Client responses
// contain at least one cloud token object; individual fields may be absent.
// Validate required values before use.
// Integer timestamps use Unix seconds; expiration strings use ISO format with
// a time zone. Use the earliest valid parent or vendor expiration as the expiry.
type CloudAccountRoleAccessCredential struct {
	// AccessCredentialExpiresAt is an optional expiration timestamp in Unix seconds.
	AccessCredentialExpiresAt *int64 `json:"accessCredentialExpiresAt,omitempty"`
	// AlibabaCloudSTSToken holds optional Alibaba Cloud STS wire fields.
	AlibabaCloudSTSToken *AlibabaCloudSTSToken `json:"alibabaCloudStsToken,omitempty"`
	// AWSSTSToken holds optional AWS STS wire fields.
	AWSSTSToken *AWSSTSToken `json:"awsStsToken,omitempty"`
	// TencentCloudSTSToken holds optional Tencent Cloud STS wire fields.
	TencentCloudSTSToken *TencentCloudSTSToken `json:"tencentCloudStsToken,omitempty"`
}

// AlibabaCloudSTSToken represents Alibaba Cloud STS wire fields.
type AlibabaCloudSTSToken struct {
	// AccessKeyID is the optional temporary access key identifier.
	AccessKeyID *string `json:"accessKeyId,omitempty"`
	// AccessKeySecret is the optional confidential access key secret.
	AccessKeySecret *string `json:"accessKeySecret,omitempty"`
	// SecurityToken is the optional confidential session token.
	SecurityToken *string `json:"securityToken,omitempty"`
	// Expiration preserves the service ISO expiration string with a time zone.
	// Parse and compare it with the parent expiration before use.
	Expiration *string `json:"expiration,omitempty"`
}

// AWSSTSToken represents AWS STS wire fields.
type AWSSTSToken struct {
	// AccessKeyID is the optional temporary access key identifier.
	AccessKeyID *string `json:"accessKeyId,omitempty"`
	// SecretAccessKey is the optional confidential access key secret.
	SecretAccessKey *string `json:"secretAccessKey,omitempty"`
	// SessionToken is the optional confidential session token.
	SessionToken *string `json:"sessionToken,omitempty"`
	// Expiration preserves the service ISO expiration string with a time zone.
	// Parse and compare it with the parent expiration before use.
	Expiration *string `json:"expiration,omitempty"`
}

// TencentCloudSTSToken represents Tencent Cloud STS wire fields.
type TencentCloudSTSToken struct {
	// TmpSecretID is the optional temporary secret identifier.
	TmpSecretID *string `json:"tmpSecretId,omitempty"`
	// TmpSecretKey is the optional confidential temporary secret key.
	TmpSecretKey *string `json:"tmpSecretKey,omitempty"`
	// Token is the optional confidential session token.
	Token *string `json:"token,omitempty"`
	// Expiration preserves the service ISO expiration string with a time zone.
	// Parse and compare it with ExpiredTime and the parent expiration before use.
	Expiration *string `json:"expiration,omitempty"`
	// ExpiredTime is an optional expiration timestamp in Unix seconds.
	ExpiredTime *int64 `json:"expiredTime,omitempty"`
}
