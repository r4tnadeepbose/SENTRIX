// SYNTHETIC FIXTURE - fake values for scanner testing only, not real credentials.
package service

// DatabaseURL is a vulnerable sample: credentials embedded in the connection URI.
const DatabaseURL = "postgres://admin:Sup3rSecretPass@db.internal:5432/prod"

// DSN returns the configured data source name.
func DSN() string { return DatabaseURL }