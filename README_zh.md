# IDaaS Go PAM Client SDK

[English](README.md) | 简体中文

通过 IDaaS PAM 获取 API Key、生成和获取 JWT、管理认证令牌，以及获取阿里云、AWS 和腾讯云的临时访问凭证（STS）。

PAM SDK 负责调用 Developer API；[Core SDK](https://github.com/cloud-idaas/idaas-go-core-sdk)负责应用认证及 AccessToken 的缓存和刷新。需要将 STS 自动接入云 SDK 时，使用对应的云 Adapter。

[快速开始](#快速开始获取-api-key) · [常用操作](#常用操作) · [客户端配置](#自定义客户端) · [错误处理](#错误处理)

## 安装

要求 Go 1.18 及以上版本，建议使用仍受支持且已安装安全补丁的 Go 版本。在已有 Go module 中安装：

```sh
go get github.com/cloud-idaas/idaas-go-pam-client-sdk
```

新项目先执行 `go mod init example.com/pam-demo`。Core SDK 会作为依赖一并安装。

## 快速开始：获取 API Key

### 1. 准备应用和凭据

在 IDaaS 中准备一个应用，为其授予所需的 PAM 操作及目标资源访问权限，并创建或选择要读取的 API Key 凭据。准备以下信息：

| 信息 | 用途 |
| --- | --- |
| 实例 ID、应用 Client ID、Client Secret | 让 Core SDK 以应用身份认证 |
| Issuer、Token Endpoint | 使用该应用对应的认证配置值 |
| Developer API Endpoint | 目标实例的 Developer API 基础端点，不附加 `/v2/{instanceId}` 或操作路径 |
| 凭据标识符 | API Key 凭据的业务标识，作为 `GetAPIKey` 的参数 |

以下示例使用 `CLIENT_SECRET_POST` 认证。其他认证方式见 [Core SDK 配置说明](https://github.com/cloud-idaas/idaas-go-core-sdk/blob/main/README_zh.md)。申请 scope 不等于授予权限，应用仍需获得目标操作的授权。

### 2. 配置认证信息

将以下内容保存为仓库外的 `client-config.json`，把示例值替换为你的环境配置。也可以复制[配置模板](samples/client-config.example.json)。

```json
{
  "clientId": "app_example",
  "idaasInstanceId": "idaas_example",
  "issuer": "https://tenant.example.invalid",
  "tokenEndpoint": "https://tenant.example.invalid/api/v2/iauths_system/oauth2/token",
  "developerApiEndpoint": "https://developerapi.example.invalid",
  "scope": "urn:cloud:idaas:pam|.all",
  "authnConfiguration": {
    "identityType": "CLIENT",
    "authnMethod": "CLIENT_SECRET_POST",
    "clientSecretEnvVarName": "IDAAS_CLIENT_SECRET"
  },
  "httpConfiguration": {
    "connectTimeout": 5000,
    "readTimeout": 10000,
    "unsafeIgnoreSslCert": false
  }
}
```

`clientSecretEnvVarName` 填写环境变量名，密钥值由运行环境提供。使用可信的 HTTPS 端点，并保持证书校验开启。

```sh
export CLOUD_IDAAS_CONFIG_PATH="/absolute/path/to/client-config.json"
export IDAAS_CLIENT_SECRET="your-client-secret"
export PAM_CREDENTIAL_IDENTIFIER="your-api-key-credential-identifier"
```

以上均为占位值；真实密钥请通过运行环境或密钥管理系统注入，不要写入配置文件或提交到仓库。

### 3. 创建客户端并调用

保存为 `main.go`：

```go
package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/cloud-idaas/idaas-go-core-sdk/factory"
	pam "github.com/cloud-idaas/idaas-go-pam-client-sdk"
)

func main() {
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
		return err
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
	if key == nil {
		return errors.New("no API key is available for this credential")
	}
	// Pass *key to the service that requires it; do not print the key.
	fmt.Println("API key retrieved")
	return nil
}
```

```sh
go mod tidy
go run .
```

成功时输出 `API key retrieved`。实际密钥通过 `*key` 取得，可传给需要它的业务客户端。在 `err == nil` 时，`key == nil` 表示服务端明确返回没有可用的 API Key；请求失败则返回非 nil 的 `error`。

## 常用操作

下面的函数可放入快速开始的 `main.go`，复用其 import。切换到这些操作时，删除 `run` 开头读取和检查 `PAM_CREDENTIAL_IDENTIFIER` 的代码；保留 Core 初始化、客户端创建、关闭和 context 设置，用下表中的调用替换 API Key 查询及其后的返回逻辑，并替换各示例中的业务标识。

| 示例 | `run` 中的调用 |
| --- | --- |
| 生成 JWT | `return generateJWT(ctx, client)` |
| 分页查询 | `return listTokens(ctx, client)` |
| 校验 Token | `return checkToken(ctx, client, os.Getenv("PAM_TOKEN"))`，由运行环境通过 `PAM_TOKEN` 提供待校验 Token |
| 获取 STS | `return obtainSTS(ctx, client)` |

所有业务方法均以非 nil 的 `context.Context` 为首参，以 `error` 为末尾返回值。建议复用客户端，为每次业务操作设置合适的 context 截止时间。

### 生成 JWT

凭据提供者需支持 JWT 签发，subject 和 audience 需满足该提供者的配置。

```go
func generateJWT(ctx context.Context, client *pam.Client) error {
	lifetime := int64(300)
	includeShortToken := true
	result, err := client.GenerateJWTAuthenticationToken(ctx, pam.GenerateJWTAuthenticationTokenRequest{
		CredentialProviderIdentifier: "your-jwt-provider-identifier",
		Subject:                      "your-subject",
		Audiences:                    []string{"your-audience"},
		Expiration:                   &lifetime,
		IncludeDerivedShortToken:     &includeShortToken,
	})
	if err != nil {
		return err
	}
	// Use result.JWTContent.JWTValue to authenticate to the target service.
	// result.JWTContent.DerivedShortToken is optional; check for nil before use.
	fmt.Printf("Token created: %s\n", result.AuthenticationTokenID)
	return nil
}
```

`Expiration` 单位为秒，不传时使用服务端默认值。可通过 `Issuer` 指定签发者，通过 `CustomClaims` 传入自定义声明。字段约束见[请求类型说明](models.go)。

生成结果包含 `AuthenticationTokenID` 和 `JWTContent`。后续可调用：

| 场景 | 调用及返回值 |
| --- | --- |
| 按消费者和 Token ID 获取 JWT | `ObtainJWTAuthenticationToken(ctx, consumerID, authenticationTokenID)` → `*JWTContent, error` |
| 用派生短 Token 换取 JWT | `ObtainJWTAuthenticationTokenByDerivedShortToken(ctx, shortToken)` → `*JWTContent, error` |

`JWTContent.JWTValue` 是 JWT 明文；`DerivedShortToken` 为可选指针。JWT 和短 Token 都应作为凭据使用，不要打印。

### 分页查询 Token

```go
func listTokens(ctx context.Context, client *pam.Client) error {
	pageSize := int64(20)
	revoked := false
	input := pam.ListAuthenticationTokensRequest{
		ConsumerID:                   "your-consumer-id",
		CredentialProviderIdentifier: "your-jwt-provider-identifier",
		MaxResults:                   &pageSize,
		Revoked:                      &revoked,
	}
	for {
		page, err := client.ListAuthenticationTokens(ctx, input)
		if err != nil {
			return err
		}
		fmt.Printf("Tokens in this page: %d\n", len(page.Entities))
		if page.NextToken == "" {
			return nil
		}
		if page.NextToken == input.NextToken {
			return errors.New("server repeated the pagination cursor")
		}
		input.NextToken = page.NextToken
	}
}
```

`ConsumerID` 是 Token 所属消费者的 ID；`CredentialProviderIdentifier` 是凭据提供者的业务标识，不能用响应元数据中的 `CredentialProviderID` 替代。响应 `NextToken` 为空表示结束，否则原样用于下一页。

可选的 `Revoked`、`Expired` 使用 `*bool`：nil 省略该筛选参数，默认行为由服务端决定；指向 false 或 true 的指针分别显式筛选对应状态。`MaxResults` 为可选正整数。Token 元数据时间戳单位为 Unix 毫秒。

### 校验、吊销和恢复 Token

```go
func checkToken(ctx context.Context, client *pam.Client, token string) error {
	active, err := client.ValidateAuthenticationToken(ctx, token, nil)
	if err != nil {
		return err
	}
	fmt.Printf("Token active: %t\n", active)
	return nil
}
```

| 操作 | 调用及返回值 |
| --- | --- |
| 校验单个 Token | `ValidateAuthenticationToken(ctx, token, nil)` → `bool, error` |
| 吊销单个 Token | `RevokeAuthenticationToken(ctx, token, nil)` → `error` |
| 恢复单个 Token | `ReinstateAuthenticationToken(ctx, token, nil)` → `error` |
| 按消费者吊销 | `RevokeAuthenticationTokenByConsumer(ctx, consumerID, providerIdentifier)` → `error` |
| 按消费者恢复 | `ReinstateAuthenticationTokenByConsumer(ctx, consumerID, providerIdentifier)` → `error` |

单 Token 接口接收 **Token 明文，不是 Token ID**。最后一个参数为可选的 `*pam.TokenOptions`，无提示时传 nil；需要时设置 `TokenTypeHint`。校验返回 `false, nil` 表示 Token 未激活。按消费者操作会影响该消费者在指定凭据提供者下的所有匹配 Token。

### 获取云角色 STS

```go
func obtainSTS(ctx context.Context, client *pam.Client) error {
	result, err := client.ObtainAccessCredential(ctx, "your-cloud-role-external-id")
	if err != nil {
		return err
	}
	// Select the token for your cloud, then validate its fields and expiration
	// before constructing cloud SDK credentials. Do not log credential values.
	fmt.Printf("STS available: Alibaba Cloud=%t AWS=%t Tencent Cloud=%t\n",
		result.AlibabaCloudSTSToken != nil,
		result.AWSSTSToken != nil,
		result.TencentCloudSTSToken != nil)
	return nil
}
```

参数使用云账号角色的外部 ID。返回值按云厂商提供 `AlibabaCloudSTSToken`、`AWSSTSToken` 或 `TencentCloudSTSToken`，使用前检查对应对象和所需字段是否存在。

STS 的字段及有效期约定见[响应类型说明](models.go)。PAM 不缓存 STS；需要自动刷新和云 SDK 集成时，使用[阿里云](https://github.com/cloud-idaas/idaas-go-akless-alibabacloud-adapter)、[AWS](https://github.com/cloud-idaas/idaas-go-akless-aws-adapter)或[腾讯云](https://github.com/cloud-idaas/idaas-go-akless-tencent-adapter) Adapter。

可直接运行的完整工作流及其环境变量见 [samples](samples/README.md)。其中 JWT 和生命周期示例会真实生成、吊销或恢复 Token，请使用专门的测试资源。

## 自定义客户端

多数应用使用快速开始中的 `NewDefaultClient()` 即可。已有 Core Provider，或需要指定实例、端点、HTTP 配置时，使用 `NewClient(Config)` 或 Builder。

例如，在 `factory.Init()` 成功后，用以下代码替换默认客户端的构造部分：

```go
provider, err := factory.GetIDaaSCredentialProviderByScope(pam.Scope)
if err != nil {
	return err
}
client, err := pam.NewClient(pam.Config{
	DeveloperAPIEndpoint: "https://your-developer-api-endpoint",
	IDaaSInstanceID:      "your-idaas-instance-id",
	CredentialProvider:   provider,
})
if err != nil {
	return err
}
defer func() { _ = client.Close() }()
```

同一 Provider 也可通过 Builder 注入，`Build()` 返回 `(*pam.Client, error)`，同样需要检查错误并关闭客户端：

```go
client, err := pam.NewBuilder().
	DeveloperAPIEndpoint("https://your-developer-api-endpoint").
	IDaaSInstanceID("your-idaas-instance-id").
	CredentialProvider(provider).
	Build()
```

| `pam.Config` 字段 / Builder 方法 | 用途与默认行为 |
| --- | --- |
| `DeveloperAPIEndpoint` | Developer API 基础端点；空串从 Core 读取 |
| `IDaaSInstanceID` | 目标实例 ID；空串从 Core 读取 |
| `CredentialProvider` | Core Provider；nil 从 Core 解析 `pam.Scope` 对应的 Provider |
| `HTTPConfiguration` | SDK 自建 HTTP 客户端的配置；超时单位为毫秒 |
| `HTTPClient` | 自定义 Core `http.HttpClient`；nil 使用 SDK 自建客户端 |
| `Logger` | Core Logger；nil 使用 Core 默认 Logger |

显式提供端点、实例 ID 和 Provider 时，无需初始化 Core 工厂；缺少任一项时需先初始化 Core，以补齐配置。

`HTTPConfiguration` 仅作用于 SDK 自建 HTTP 客户端，默认连接超时为 5 秒、整个 HTTP 请求超时为 10 秒，可通过 context 提前取消或限时。配置的继承与覆盖规则见 [Config 说明](config.go)。注入的 HTTP 客户端和 Provider 使用各自的传输配置。

Client 可并发复用，不要复制客户端或在请求完成前修改请求数据；Builder 不支持并发配置。应用退出前先等待业务请求结束，再调用 `Close()`。它不会取消或等待进行中的请求，也不会关闭调用方注入的依赖。更多生命周期约定见[包文档](doc.go)。

## 错误处理

可直接返回或处理调用错误。需要区分取消、超时或 SDK 错误时，在快速开始的 import 中增加：

```go
coreerrors "github.com/cloud-idaas/idaas-go-core-sdk/errors"
```

并在 `main` 的错误分支调用 `reportError(err)`：

```go
func reportError(err error) {
	var sdkErr coreerrors.IDaaSError
	switch {
	case errors.Is(err, context.Canceled):
		fmt.Fprintln(os.Stderr, "Operation canceled")
	case errors.Is(err, context.DeadlineExceeded):
		fmt.Fprintln(os.Stderr, "Operation timed out")
	case errors.Is(err, pam.ErrClosed):
		fmt.Fprintln(os.Stderr, "PAM client is closed")
	case errors.As(err, &sdkErr):
		fmt.Fprintf(os.Stderr, "code=%s requestID=%s: %v\n",
			sdkErr.ErrorCode(), sdkErr.RequestId(), err)
	default:
		fmt.Fprintln(os.Stderr, err)
	}
}
```

SDK 使用 Core 错误类型；排查服务端请求时保留错误码和 Request ID。

SDK 不自动重试业务操作。特别是 JWT 生成不保证幂等，超时、取消或响应解析失败时，先核对服务端结果，再决定是否重试。日志中不要输出密钥、Token 或原始凭据响应。安全配置与传输说明见[安全策略](SECURITY.md)。

## 更多资料

### 使用参考

- [完整示例](samples/README.md)
- [请求与响应类型](models.go)
- [Go 包文档](https://pkg.go.dev/github.com/cloud-idaas/idaas-go-pam-client-sdk)

### 支持与贡献

- [问题反馈](https://github.com/cloud-idaas/idaas-go-pam-client-sdk/issues)
- [贡献指南](CONTRIBUTING.md)
- [安全策略](SECURITY.md)

### 发布与许可

- [发布说明](RELEASE.md)
- [版本记录](CHANGELOG.md)
- [Apache License 2.0](LICENSE)
