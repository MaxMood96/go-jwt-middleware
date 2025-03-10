module example.com/http-jwks

go 1.23.0

require (
	github.com/auth0/go-jwt-middleware/v2 v2.2.2
	gopkg.in/go-jose/go-jose.v2 v2.6.3
)

replace github.com/auth0/go-jwt-middleware/v2 => ./../../

require (
	golang.org/x/crypto v0.35.0 // indirect
	golang.org/x/sync v0.11.0 // indirect
)
