package pam

import (
	"bytes"
	"encoding/json"
	"strings"

	"github.com/cloud-idaas/idaas-go-core-sdk/domain"
	coreerrors "github.com/cloud-idaas/idaas-go-core-sdk/errors"
)

type wireObject map[string]json.RawMessage

func decodeObject(encoded []byte) (wireObject, error) {
	var object wireObject
	if err := json.Unmarshal(encoded, &object); err != nil {
		return nil, coreerrors.NewEncodingError("DecodeFailed", "PAM response must be a JSON object", nil)
	}
	if object == nil {
		return nil, responseError("object")
	}
	return object, nil
}

func readField[T any](object wireObject, name string, mandatory bool) (*T, error) {
	raw, exists := object[name]
	if !exists {
		if mandatory {
			return nil, responseError(name)
		}
		return nil, nil
	}
	if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return nil, responseError(name)
	}
	var value T
	if err := json.Unmarshal(raw, &value); err != nil {
		return nil, responseError(name)
	}
	return &value, nil
}

func requiredResponseString(object wireObject, name string) (*string, error) {
	value, err := readField[string](object, name, true)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(*value) == "" {
		return nil, responseError(name)
	}
	return value, nil
}

func parseAPIKey(encoded []byte) (*string, error) {
	root, err := decodeObject(encoded)
	if err != nil {
		return nil, err
	}
	content, err := readField[wireObject](root, "credentialContent", true)
	if err != nil {
		return nil, err
	}
	raw, exists := (*content)["apiKeyContent"]
	if !exists {
		return nil, responseError("apiKeyContent")
	}
	if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return nil, nil
	}
	keyContent, err := decodeObject(raw)
	if err != nil {
		return nil, err
	}
	return requiredResponseString(keyContent, "apiKey")
}

func parseJWT(encoded []byte) (*JWTContent, error) {
	root, err := decodeObject(encoded)
	if err != nil {
		return nil, err
	}
	return jwtFromObject(root)
}

func jwtFromObject(root wireObject) (*JWTContent, error) {
	object, err := readField[wireObject](root, "jwtContent", true)
	if err != nil {
		return nil, err
	}
	jwt, err := requiredResponseString(*object, "jwtValue")
	if err != nil {
		return nil, err
	}
	short, err := readField[string](*object, "derivedShortToken", false)
	if err != nil {
		return nil, err
	}
	return &JWTContent{JWTValue: *jwt, DerivedShortToken: short}, nil
}

func parseJWTResponse(encoded []byte) (*JWTTokenResponse, error) {
	root, err := decodeObject(encoded)
	if err != nil {
		return nil, err
	}
	id, err := requiredResponseString(root, "authenticationTokenId")
	if err != nil {
		return nil, err
	}
	jwt, err := jwtFromObject(root)
	if err != nil {
		return nil, err
	}
	consumerType, err := readField[string](root, "consumerType", false)
	if err != nil {
		return nil, err
	}
	consumerID, err := readField[string](root, "consumerId", false)
	if err != nil {
		return nil, err
	}
	return &JWTTokenResponse{AuthenticationTokenID: *id, JWTContent: *jwt, ConsumerType: consumerType, ConsumerID: consumerID}, nil
}

func parseTokenPage(encoded []byte) (*AuthenticationTokenPage, error) {
	root, err := decodeObject(encoded)
	if err != nil {
		return nil, err
	}
	entities, err := readField[[]json.RawMessage](root, "entities", false)
	if err != nil {
		return nil, err
	}
	page := &AuthenticationTokenPage{}
	page.TotalCount, err = readField[int64](root, "totalCount", false)
	if err != nil {
		return nil, err
	}
	if page.TotalCount != nil && *page.TotalCount < 0 {
		return nil, responseError("totalCount")
	}
	page.MaxResults, err = readField[int64](root, "maxResults", false)
	if err != nil {
		return nil, err
	}
	if page.MaxResults != nil && *page.MaxResults < 0 {
		return nil, responseError("maxResults")
	}
	if raw, exists := root["nextToken"]; exists && !bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		next, err := readField[string](root, "nextToken", true)
		if err != nil {
			return nil, err
		}
		page.NextToken = *next
	}
	if entities == nil {
		// An explicit zero-result terminal page may omit the array on the wire.
		if page.TotalCount == nil || *page.TotalCount != 0 || page.MaxResults == nil || page.NextToken != "" {
			return nil, responseError("entities")
		}
		page.Entities = make([]AuthenticationToken, 0)
		return page, nil
	}
	page.Entities = make([]AuthenticationToken, 0, len(*entities))
	for _, encodedToken := range *entities {
		token, err := parseAuthenticationToken(encodedToken)
		if err != nil {
			return nil, err
		}
		page.Entities = append(page.Entities, *token)
	}
	return page, nil
}

func parseAuthenticationToken(encoded []byte) (*AuthenticationToken, error) {
	object, err := decodeObject(encoded)
	if err != nil {
		return nil, err
	}
	result := &AuthenticationToken{}
	stringsByName := map[string]**string{
		"instanceId": &result.InstanceID, "authenticationTokenId": &result.AuthenticationTokenID,
		"authenticationTokenType": &result.AuthenticationTokenType, "credentialProviderId": &result.CredentialProviderID,
		"creatorType": &result.CreatorType, "creatorId": &result.CreatorID,
		"consumerType": &result.ConsumerType, "consumerId": &result.ConsumerID,
	}
	for name, target := range stringsByName {
		*target, err = readField[string](object, name, false)
		if err != nil {
			return nil, err
		}
	}
	for name, target := range map[string]**int64{
		"createTime": &result.CreateTime, "updateTime": &result.UpdateTime, "expirationTime": &result.ExpirationTime,
	} {
		*target, err = readField[int64](object, name, false)
		if err != nil {
			return nil, err
		}
	}
	result.Revoked, err = readField[bool](object, "revoked", false)
	if err != nil {
		return nil, err
	}
	return result, nil
}

func parseCloudCredential(encoded []byte) (*CloudAccountRoleAccessCredential, error) {
	root, err := decodeObject(encoded)
	if err != nil {
		return nil, err
	}
	object, err := readField[wireObject](root, "cloudAccountRoleAccessCredential", true)
	if err != nil {
		return nil, err
	}
	result := &CloudAccountRoleAccessCredential{}
	result.AccessCredentialExpiresAt, err = readField[int64](*object, "accessCredentialExpiresAt", false)
	if err != nil {
		return nil, err
	}
	result.AlibabaCloudSTSToken, err = cloudToken[AlibabaCloudSTSToken](*object, "alibabaCloudStsToken", []string{"accessKeyId", "accessKeySecret", "securityToken", "expiration"})
	if err != nil {
		return nil, err
	}
	result.AWSSTSToken, err = cloudToken[AWSSTSToken](*object, "awsStsToken", []string{"accessKeyId", "secretAccessKey", "sessionToken", "expiration"})
	if err != nil {
		return nil, err
	}
	result.TencentCloudSTSToken, err = cloudToken[TencentCloudSTSToken](*object, "tencentCloudStsToken", []string{"tmpSecretId", "tmpSecretKey", "token", "expiration"})
	if err != nil {
		return nil, err
	}
	if result.AlibabaCloudSTSToken == nil && result.AWSSTSToken == nil && result.TencentCloudSTSToken == nil {
		return nil, responseError("cloud STS token")
	}
	return result, nil
}

func cloudToken[T any](object wireObject, name string, fields []string) (*T, error) {
	raw, exists := object[name]
	if !exists {
		return nil, nil
	}
	token, err := decodeObject(raw)
	if err != nil {
		return nil, err
	}
	// Validate field presence and null handling before typed decoding.
	for _, field := range fields {
		value, err := readField[string](token, field, false)
		if err != nil {
			return nil, err
		}
		if value != nil && strings.TrimSpace(*value) == "" {
			return nil, responseError(field)
		}
	}
	if name == "tencentCloudStsToken" {
		if _, err := readField[int64](token, "expiredTime", false); err != nil {
			return nil, err
		}
	}
	// Typed decoding uses only exact protocol field names.
	filtered := make(wireObject, len(fields)+1)
	for _, field := range fields {
		if value, exists := token[field]; exists {
			filtered[field] = value
		}
	}
	if name == "tencentCloudStsToken" {
		if value, exists := token["expiredTime"]; exists {
			filtered["expiredTime"] = value
		}
	}
	encoded, err := json.Marshal(filtered)
	if err != nil {
		return nil, responseError(name)
	}
	var result T
	if err := json.Unmarshal(encoded, &result); err != nil {
		return nil, responseError(name)
	}
	return &result, nil
}

func withResponseID(err error, response *domain.HttpResponse) error {
	switch typed := err.(type) {
	case *coreerrors.CredentialError:
		return typed.WithRequestId(response.RequestId())
	case *coreerrors.EncodingError:
		return typed.WithRequestId(response.RequestId())
	}
	return err
}
