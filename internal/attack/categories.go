package attack

// AllCategories returns the list of all known attack categories.
func AllCategories() []AttackCategory {
	return []AttackCategory{
		CategoryInjection,
		CategoryJailbreak,
		CategoryPolicy,
		CategoryToolAbuse,
	}
}

// CategoryFromString converts a string to an AttackCategory.
func CategoryFromString(s string) AttackCategory {
	switch AttackCategory(s) {
	case CategoryInjection, CategoryJailbreak, CategoryPolicy, CategoryToolAbuse, CategoryMutation:
		return AttackCategory(s)
	default:
		return CategoryUnknown
	}
}
