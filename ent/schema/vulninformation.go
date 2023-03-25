package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/field"
)

// VulnInformation holds the schema definition for the VulnInformation entity.
type VulnInformation struct {
	ent.Schema
}

// Fields of the VulnInformation.
func (VulnInformation) Fields() []ent.Field {
	return []ent.Field{
		field.String("key").Unique(),
		field.String("title").Default(""),
		field.String("description").Default(""),
		field.String("severity").Default(""),
		field.String("cve").Default(""),
		field.String("disclosure").Default(""),
		field.String("solutions").Default(""),
		field.Strings("references").Optional(),
		field.Strings("tags").Optional(),
		field.String("from").Default(""),
	}
}

// Edges of the VulnInformation.
func (VulnInformation) Edges() []ent.Edge {
	return nil
}
