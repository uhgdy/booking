package domain

type UserRepository interface {
	FindByLogin(login string) (*User, error)
	FindByID(id int) (*User, error)
	CreateUser(u *User) (int, error)
	CreateProfile(p *UserProfile) error
	AssignRoles(userID int, roleIDs []int) error
	ValidateRoles(roleIDs []int) error
}
