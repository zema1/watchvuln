package ent

//go:generate go run -mod=mod entgo.io/ent/cmd/ent generate --feature sql/upsert --feature sql/versioned-migration ./schema
//go:generate echo "generate ent succeed"
