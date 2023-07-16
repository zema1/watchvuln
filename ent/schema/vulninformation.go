package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/field"
	"time"
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
		field.Text("description").Default(""),
		field.String("severity").Default(""),
		field.String("cve").Default(""),
		field.String("disclosure").Default(""),
		field.Text("solutions").Default(""),
		field.Strings("references").Optional(),
		field.Strings("tags").Optional(),
		field.Strings("github_search").Optional(),
		field.String("from").Default(""),
		field.Bool("pushed").Default(true),
		field.Time("create_time").Default(time.Now).Immutable(),
		field.Time("update_time").Default(time.Now).UpdateDefault(time.Now),
	}
}

// Edges of the VulnInformation.
func (VulnInformation) Edges() []ent.Edge {
	return nil
}
