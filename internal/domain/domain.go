package domain

const (
	RoleAdmin   = "admin"
	RoleManager = "manager"
	RoleCashier = "cashier"
)

func IsValidRole(role string) bool {
	switch role {
	case RoleAdmin, RoleManager, RoleCashier:
		return true
	}
	return false
}
