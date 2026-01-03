# Octanox Migration Guide

## Overview

Octanox has been restructured into subpackages for better organization.
**Backwards compatibility is fully maintained** - existing code continues to work.

## Re-exports

These types are re-exported from the root `octanox` package for convenience and will remain for now:

| Root Import | Direct Import |
|-------------|---------------|
| `octanox.User` | `octanox/model.User` |
| `octanox.Context` | `octanox/ctx.Context` |
| `octanox.SubRouter` | `octanox/router.SubRouter` |
| `octanox.OAuth2UserProvider` | `octanox/auth.OAuth2UserProvider` |
| `octanox.GetRequest` | `octanox/request.GetRequest` |
| `octanox.PostRequest` | `octanox/request.PostRequest` |
| `octanox.PutRequest` | `octanox/request.PutRequest` |
| `octanox.DeleteRequest` | `octanox/request.DeleteRequest` |
| `octanox.PatchRequest` | `octanox/request.PatchRequest` |

## Preferred Imports for New Code

While the root imports work, new code may prefer direct subpackage imports:

### Before (still works)
```go
import "github.com/sevenitynet/octanox"

type MyRequest struct {
    octanox.GetRequest
    User octanox.User `user:"true"`
}

func handler(req *MyRequest) (any, octanox.Context) { ... }
```

### After (optional alternative for new code)
```go
import (
    "github.com/sevenitynet/octanox"
    "github.com/sevenitynet/octanox/ctx"
    "github.com/sevenitynet/octanox/model"
    "github.com/sevenitynet/octanox/request"
)

type MyRequest struct {
    request.GetRequest
    User model.User `user:"true"`
}

func handler(req *MyRequest) (any, ctx.Context) { ... }
```

## Subpackage Reference

| Package | Contents |
|---------|----------|
| `octanox` | Instance, New(), Run(), Authenticate(), RegisterSerializer() |
| `octanox/auth` | OAuth2UserProvider, Authenticator, BearerAuthenticator, OAuth2BearerAuthenticator, PKCE, StateMap |
| `octanox/ctx` | Context type and helpers (FromMap, FromQuery) |
| `octanox/model` | User interface |
| `octanox/request` | GetRequest, PostRequest, PutRequest, DeleteRequest, PatchRequest |
| `octanox/router` | SubRouter, Register(), RegisterPublic() |
| `octanox/middleware` | CORS, Recovery, Logger middleware |
| `octanox/serialize` | Serializer registry |
| `octanox/codegen` | TypeScript client generation |
| `octanox/errors` | Error wrapper, FailedRequest |
| `octanox/hook` | Hook type and lifecycle constants |

## No Action Required

Existing applications do not need to change any imports. The re-exports have zero runtime cost (Go type aliases).
