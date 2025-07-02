package domain

type UserRepository interface {
	FindByLogin(login string) (*User, error)
}
