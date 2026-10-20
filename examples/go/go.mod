module github.com/vocdoni/oauth/examples/go

go 1.26.0

require github.com/vocdoni/oauth/go v0.0.0

require (
	github.com/coreos/go-oidc/v3 v3.21.0 // indirect
	github.com/go-jose/go-jose/v4 v4.1.4 // indirect
	golang.org/x/oauth2 v0.37.0 // indirect
)

replace github.com/vocdoni/oauth/go => ../../go
