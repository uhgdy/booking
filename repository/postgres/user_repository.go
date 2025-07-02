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
	var roles []int

	// Сначала получаем основную информацию о пользователе
	err := r.db.QueryRow(context.Background(),
		`SELECT id, login, password FROM "user" WHERE login = $1`, login).
		Scan(&user.ID, &user.Login, &user.Password)
	if err != nil {
		return nil, err
	}

	// Затем получаем все роли пользователя
	rows, err := r.db.Query(context.Background(),
		`SELECT role_id FROM users_roles WHERE user_id = $1`, user.ID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var roleID int
		if err := rows.Scan(&roleID); err != nil {
			return nil, err
		}
		roles = append(roles, roleID)
	}

	user.Roles = roles

	return &user, nil
}
