package domain

const (
	RoleAdmin   = "admin"
	RoleManager = "manager"
	RoleCashier = "cashier"
)

// IsValidRole reports whether role is one of the known user roles.
//
// ENG: Valid roles are admin, manager and cashier.
// LAO: ກວດວ່າ role ເປັນ admin, manager ຫຼື cashier ຫຼືບໍ່.
//
// @param role - role name to check
// @returns true if the role is known
func IsValidRole(role string) bool {
	switch role {
	case RoleAdmin, RoleManager, RoleCashier:
		return true
	}
	return false
}
