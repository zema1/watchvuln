// Code generated by ent, DO NOT EDIT.

package vulninformation

import (
	"entgo.io/ent/dialect/sql"
)

const (
	// Label holds the string label denoting the vulninformation type in the database.
	Label = "vuln_information"
	// FieldID holds the string denoting the id field in the database.
	FieldID = "id"
	// FieldKey holds the string denoting the key field in the database.
	FieldKey = "key"
	// FieldTitle holds the string denoting the title field in the database.
	FieldTitle = "title"
	// FieldDescription holds the string denoting the description field in the database.
	FieldDescription = "description"
	// FieldSeverity holds the string denoting the severity field in the database.
	FieldSeverity = "severity"
	// FieldCve holds the string denoting the cve field in the database.
	FieldCve = "cve"
	// FieldDisclosure holds the string denoting the disclosure field in the database.
	FieldDisclosure = "disclosure"
	// FieldSolutions holds the string denoting the solutions field in the database.
	FieldSolutions = "solutions"
	// FieldReferences holds the string denoting the references field in the database.
	FieldReferences = "references"
	// FieldTags holds the string denoting the tags field in the database.
	FieldTags = "tags"
	// FieldFrom holds the string denoting the from field in the database.
	FieldFrom = "from"
	// FieldPushed holds the string denoting the pushed field in the database.
	FieldPushed = "pushed"
	// Table holds the table name of the vulninformation in the database.
	Table = "vuln_informations"
)

// Columns holds all SQL columns for vulninformation fields.
var Columns = []string{
	FieldID,
	FieldKey,
	FieldTitle,
	FieldDescription,
	FieldSeverity,
	FieldCve,
	FieldDisclosure,
	FieldSolutions,
	FieldReferences,
	FieldTags,
	FieldFrom,
	FieldPushed,
}

// ValidColumn reports if the column name is valid (part of the table columns).
func ValidColumn(column string) bool {
	for i := range Columns {
		if column == Columns[i] {
			return true
		}
	}
	return false
}

var (
	// DefaultTitle holds the default value on creation for the "title" field.
	DefaultTitle string
	// DefaultDescription holds the default value on creation for the "description" field.
	DefaultDescription string
	// DefaultSeverity holds the default value on creation for the "severity" field.
	DefaultSeverity string
	// DefaultCve holds the default value on creation for the "cve" field.
	DefaultCve string
	// DefaultDisclosure holds the default value on creation for the "disclosure" field.
	DefaultDisclosure string
	// DefaultSolutions holds the default value on creation for the "solutions" field.
	DefaultSolutions string
	// DefaultFrom holds the default value on creation for the "from" field.
	DefaultFrom string
	// DefaultPushed holds the default value on creation for the "pushed" field.
	DefaultPushed bool
)

// Order defines the ordering method for the VulnInformation queries.
type Order func(*sql.Selector)

// ByID orders the results by the id field.
func ByID(opts ...sql.OrderTermOption) Order {
	return sql.OrderByField(FieldID, opts...).ToFunc()
}

// ByKey orders the results by the key field.
func ByKey(opts ...sql.OrderTermOption) Order {
	return sql.OrderByField(FieldKey, opts...).ToFunc()
}

// ByTitle orders the results by the title field.
func ByTitle(opts ...sql.OrderTermOption) Order {
	return sql.OrderByField(FieldTitle, opts...).ToFunc()
}

// ByDescription orders the results by the description field.
func ByDescription(opts ...sql.OrderTermOption) Order {
	return sql.OrderByField(FieldDescription, opts...).ToFunc()
}

// BySeverity orders the results by the severity field.
func BySeverity(opts ...sql.OrderTermOption) Order {
	return sql.OrderByField(FieldSeverity, opts...).ToFunc()
}

// ByCve orders the results by the cve field.
func ByCve(opts ...sql.OrderTermOption) Order {
	return sql.OrderByField(FieldCve, opts...).ToFunc()
}

// ByDisclosure orders the results by the disclosure field.
func ByDisclosure(opts ...sql.OrderTermOption) Order {
	return sql.OrderByField(FieldDisclosure, opts...).ToFunc()
}

// BySolutions orders the results by the solutions field.
func BySolutions(opts ...sql.OrderTermOption) Order {
	return sql.OrderByField(FieldSolutions, opts...).ToFunc()
}

// ByFrom orders the results by the from field.
func ByFrom(opts ...sql.OrderTermOption) Order {
	return sql.OrderByField(FieldFrom, opts...).ToFunc()
}

// ByPushed orders the results by the pushed field.
func ByPushed(opts ...sql.OrderTermOption) Order {
	return sql.OrderByField(FieldPushed, opts...).ToFunc()
}
