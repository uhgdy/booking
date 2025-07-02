package postgres

import (
	"auth_project/domain"
	"context"

	"github.com/jackc/pgx/v5/pgxpool"
)

type UserRepository struct {
	db *pgxpool.Pool
}

func NewUserRepository(db *pgxpool.Pool) *UserRepository {
	return &UserRepository{db: db}
}

func (r *UserRepository) FindByLogin(login string) (*domain.User, error) {
	var user domain.User

	err := r.db.QueryRow(context.Background(),
		`SELECT u.id, u.login, u.password, COALESCE(ur.role_id, 1)
		 FROM "user" u
		 LEFT JOIN users_roles ur ON ur.user_id = u.id
		 WHERE u.login = $1`, login).Scan(&user.ID, &user.Login, &user.Password, &user.RoleID)

	if err != nil {
		return nil, err
	}

	return &user, nil
}
