# Octanox

A lightweight, opinionated Go web framework built on top of [Gin](https://github.com/gin-gonic/gin). Octanox provides a structured approach to building REST APIs with automatic request parsing, authentication, serialization, and TypeScript client code generation.

## Installation

```bash
go get github.com/sevenitynet/octanox
```

## Quick Start

```go
package main

import "github.com/sevenitynet/octanox"

type HelloRequest struct {
    octanox.GetRequest
    Name string `query:"name"`
}

type HelloResponse struct {
    Message string `json:"message"`
}

func main() {
    app := octanox.New()

    app.RegisterPublic("/hello", func(req *HelloRequest) HelloResponse {
        return HelloResponse{Message: "Hello, " + req.Name}
    })

    app.Run()
}
```

## Features

- **Automatic Request Parsing**: Define request structs with tags for path params, query params, headers, and JSON body
- **Built-in Authentication**: Support for Bearer JWT, Basic Auth, API Key, and OAuth2/OIDC
- **Response Serialization**: Register custom serializers to transform responses
- **TypeScript Code Generation**: Automatically generate TypeScript client code for your API
- **Lifecycle Hooks**: Hook into init, before_start, start, and shutdown events

## Package Structure

Octanox is organized into focused subpackages:

| Package | Description |
|---------|-------------|
| `octanox` | Core framework - Instance, routing, authentication builder |
| `octanox/auth` | Authentication implementations (Bearer, Basic, API Key, OAuth2) |
| `octanox/ctx` | Context type for passing data through serializers |
| `octanox/model` | User interface definition |
| `octanox/request` | Request types (GetRequest, PostRequest, etc.) |
| `octanox/router` | SubRouter for route grouping |
| `octanox/middleware` | CORS, Logger, Recovery middleware |
| `octanox/serialize` | Serializer registry |
| `octanox/codegen` | TypeScript client code generation |
| `octanox/errors` | Error handling utilities |
| `octanox/hook` | Lifecycle hook constants |

## Request Handling

Define request structs with tags to automatically parse incoming requests:

```go
type CreateUserRequest struct {
    octanox.PostRequest
    User   octanox.User  `user:"true"`              // Authenticated user (required)
    ID     string        `path:"id"`                 // URL path parameter
    Filter string        `query:"filter"`            // Query parameter
    Token  string        `header:"X-Token"`          // Header value
    Body   *CreateUserBody `body:"true"`             // JSON body
}
```

### Available Tags

| Tag | Description |
|-----|-------------|
| `path:"name"` | Extract from URL path parameter |
| `query:"name"` | Extract from query string |
| `header:"name"` | Extract from request header |
| `body:"true"` | Parse JSON body into field |
| `user:"true"` | Inject authenticated user (required) |
| `user:"optional"` | Inject authenticated user (optional) |
| `gin:"true"` | Inject raw `*gin.Context` |
| `optional:"true"` | Mark query/header as optional |

## Authentication

### Bearer JWT

```go
app := octanox.New()

app.Authenticate(&myUserProvider{}).Bearer("jwt-secret", "/auth")
```

### OAuth2/OIDC

```go
app.Authenticate(&myOAuth2Provider{}).
    BearerOAuth2(
        oauth2Endpoint,
        []string{"openid", "profile"},
        clientID,
        clientSecret,
        "https://myapp.com",
        "/dashboard",
        "jwt-secret",
        "/auth",
    ).
    EnableOIDCValidation("https://issuer.example.com").
    EnableCookieAuth("session", ".myapp.com", true)
```

### Basic Auth

```go
app.Authenticate(&myUserProvider{}).Basic()
```

### API Key

```go
app.Authenticate(&myUserProvider{}).ApiKey()
```

## Serialization

Register serializers to transform database entities into DTOs:

```go
app.RegisterSerializer(db.User{}, func(u db.User, ctx octanox.Context) UserDTO {
    return UserDTO{
        ID:   u.ID,
        Name: u.Name,
    }
})
```

## Lifecycle Hooks

```go
app.Hook(hook.Hook_Init, func(i *octanox.Instance) {
    // Called when framework initializes
})

app.Hook(hook.Hook_BeforeStart, func(i *octanox.Instance) {
    // Called before server starts (register routes here)
})

app.Hook(hook.Hook_Start, func(i *octanox.Instance) {
    // Called when server starts
})

app.Hook(hook.Hook_Shutdown, func(i *octanox.Instance) {
    // Called on graceful shutdown
})
```

## Error Handling

Register error handlers for centralized error logging:

```go
app.ErrorHandler(func(err error) {
    sentry.CaptureException(err)
})
```

In handlers, use `Failed()` to abort with a specific status:

```go
func handler(req *MyRequest) Response {
    if !valid {
        req.Failed(400, "Invalid request")
    }
    return Response{}
}
```

## TypeScript Code Generation

Set environment variables and run in dry-run mode:

```bash
NOX__DRY_RUN=true NOX__CLIENT_DIR=./frontend/src/api go run .
```

This generates a TypeScript client with typed functions for all registered routes.

## Environment Variables

| Variable | Description |
|----------|-------------|
| `NOX__CORS_ALLOWED_ORIGINS` | CORS allowed origins (`*` for all) |
| `NOX__DRY_RUN` | Enable dry-run mode for code generation |
| `NOX__CLIENT_DIR` | Output directory for generated TypeScript |
| `NOX__GEN_OMIT_URL` | URL prefix to omit from generated function names |

## Version

```go
import "github.com/sevenitynet/octanox"

fmt.Println(octanox.Version) // "1.0.0"
```

## License

MIT
