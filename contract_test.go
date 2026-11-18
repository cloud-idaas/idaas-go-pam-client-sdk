package pam_test

import (
	"context"
	"encoding/json"
	"os"
	"reflect"
	"testing"

	pam "github.com/cloud-idaas/idaas-go-pam-client-sdk"
)

type publicOperation struct {
	ID       string            `json:"id"`
	Bindings map[string]string `json:"bindings"`
	HTTP     struct {
		Method string `json:"method"`
		Path   string `json:"path"`
		Bearer bool   `json:"bearer"`
	} `json:"http"`
	Required      []string `json:"required"`
	Result        string   `json:"result"`
	ImplementedIn []string `json:"implementedIn"`
}

type publicContract struct {
	SchemaVersion int               `json:"schemaVersion"`
	BasePath      string            `json:"basePath"`
	Clients       map[string]string `json:"clients"`
	Operations    []publicOperation `json:"operations"`
}

func readPublicContract(t *testing.T) publicContract {
	t.Helper()
	encoded, err := os.ReadFile("contracts/pam-api.json")
	if err != nil {
		t.Fatal(err)
	}
	var contract publicContract
	if err := json.Unmarshal(encoded, &contract); err != nil {
		t.Fatal(err)
	}
	if contract.SchemaVersion != 1 || contract.BasePath != "/v2/{instanceId}" || contract.Clients["go"] != "pam.Client" {
		t.Fatal("invalid public contract identity")
	}
	return contract
}

func TestPublicContractSurface(t *testing.T) {
	contract := readPublicContract(t)
	client := reflect.TypeOf((*pam.Client)(nil))
	contextType := reflect.TypeOf((*context.Context)(nil)).Elem()
	errorType := reflect.TypeOf((*error)(nil)).Elem()
	seen := make(map[string]bool)
	results := map[string]reflect.Type{
		"nullableApiKey":                   reflect.TypeOf((*string)(nil)),
		"jwtTokenResponse":                 reflect.TypeOf((*pam.JWTTokenResponse)(nil)),
		"jwtContent":                       reflect.TypeOf((*pam.JWTContent)(nil)),
		"authenticationTokenPage":          reflect.TypeOf((*pam.AuthenticationTokenPage)(nil)),
		"boolean":                          reflect.TypeOf(false),
		"cloudAccountRoleAccessCredential": reflect.TypeOf((*pam.CloudAccountRoleAccessCredential)(nil)),
	}
	for _, operation := range contract.Operations {
		implemented := make(map[string]bool)
		for _, language := range operation.ImplementedIn {
			if implemented[language] || contract.Clients[language] == "" {
				t.Fatalf("invalid implementation scope for %s: %s", operation.ID, language)
			}
			implemented[language] = true
		}
		if !implemented["go"] {
			t.Fatalf("Go operation %s must declare its implementation", operation.ID)
		}
		method, exists := client.MethodByName(operation.Bindings["go"])
		if !exists || seen[method.Name] || operation.ID == "" {
			t.Fatalf("missing or duplicate Go operation %q", operation.ID)
		}
		seen[method.Name] = true
		if method.Type.NumIn() < 2 || method.Type.In(1) != contextType || method.Type.NumOut() == 0 || method.Type.Out(method.Type.NumOut()-1) != errorType {
			t.Fatalf("%s must accept context first and return error last", method.Name)
		}
		if operation.Result == "void" {
			if method.Type.NumOut() != 1 {
				t.Fatalf("%s must return only error", method.Name)
			}
		} else if want, exists := results[operation.Result]; !exists || method.Type.NumOut() != 2 || method.Type.Out(0) != want {
			t.Fatalf("%s has an unexpected public result type", method.Name)
		}
		for _, language := range []string{"java", "python", "typescript"} {
			if operation.Bindings[language] == "" {
				t.Fatalf("missing %s name mapping for %s", language, method.Name)
			}
		}
	}
	if len(seen) != client.NumMethod()-1 { // Close is a lifecycle method, not a remote operation.
		t.Fatal("public remote methods and contract operations differ")
	}
}

func TestConstructionContractSurface(t *testing.T) {
	var contract struct {
		SchemaVersion int `json:"schemaVersion"`
		Clients       map[string]struct {
			Type           string `json:"type"`
			Explicit       string `json:"explicit"`
			Default        string `json:"default"`
			BuilderType    string `json:"builderType"`
			BuilderFactory string `json:"builderFactory"`
			Build          string `json:"build"`
		} `json:"clients"`
		Fields []struct {
			ID       string            `json:"id"`
			Bindings map[string]string `json:"bindings"`
		} `json:"fields"`
	}
	encoded, err := os.ReadFile("contracts/pam-construction.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(encoded, &contract); err != nil {
		t.Fatal(err)
	}
	goClient := contract.Clients["go"]
	clientType := reflect.TypeOf((*pam.Client)(nil))
	builderType := reflect.TypeOf((*pam.Builder)(nil))
	errorType := reflect.TypeOf((*error)(nil)).Elem()
	if contract.SchemaVersion != 1 || goClient.Type != clientType.Elem().Name() || goClient.BuilderType != builderType.Elem().Name() {
		t.Fatal("invalid construction contract identity")
	}
	constructors := map[string]interface{}{
		"NewClient":        pam.NewClient,
		"NewDefaultClient": pam.NewDefaultClient,
		"NewBuilder":       pam.NewBuilder,
	}
	for _, signature := range []struct {
		name string
		want reflect.Type
	}{
		{goClient.Explicit, reflect.TypeOf((*func(pam.Config) (*pam.Client, error))(nil)).Elem()},
		{goClient.Default, reflect.TypeOf((*func() (*pam.Client, error))(nil)).Elem()},
		{goClient.BuilderFactory, reflect.TypeOf((*func() *pam.Builder)(nil)).Elem()},
	} {
		if reflect.TypeOf(constructors[signature.name]) != signature.want {
			t.Fatalf("unexpected constructor signature for %s", signature.name)
		}
	}
	build, exists := builderType.MethodByName(goClient.Build)
	if !exists || build.Type.NumIn() != 1 || build.Type.NumOut() != 2 || build.Type.Out(0) != clientType || build.Type.Out(1) != errorType {
		t.Fatal("unexpected Build signature")
	}
	configType := reflect.TypeOf(pam.Config{})
	seen := make(map[string]bool)
	for _, field := range contract.Fields {
		name := field.Bindings["go"]
		configField, exists := configType.FieldByName(name)
		method, found := builderType.MethodByName(name)
		if field.ID == "" || seen[name] || !exists || !found {
			t.Fatalf("missing or duplicate Builder configuration method %q", name)
		}
		seen[name] = true
		if method.Type.NumIn() != 2 || method.Type.In(1) != configField.Type || method.Type.NumOut() != 1 || method.Type.Out(0) != builderType {
			t.Fatalf("unexpected Builder signature for %s", name)
		}
	}
	if len(seen) != configType.NumField() || builderType.NumMethod() != len(seen)+1 {
		t.Fatal("Config fields, Builder methods and construction mappings differ")
	}
}
