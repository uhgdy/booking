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

// loadRoles загружает список структур Role для пользователя
func (r *UserRepository) loadRoles(ctx context.Context, userID int) ([]domain.Role, error) {
	query := `
	SELECT r.id, r.name
	FROM role r
	JOIN users_roles ur ON ur.role_id = r.id
	WHERE ur.user_id = $1
	`
	rows, err := r.db.Query(ctx, query, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var roles []domain.Role
	for rows.Next() {
		var rl domain.Role
		if err := rows.Scan(&rl.ID, &rl.Name); err != nil {
			return nil, err
		}
		roles = append(roles, rl)
	}
	return roles, nil
}

// FindByLogin находит пользователя по логину и загружает его роли
func (r *UserRepository) FindByLogin(login string) (*domain.User, error) {
	ctx := context.Background()
	var user domain.User
	// Получаем базовые поля: ID, login, password, имя и биографию, если они есть
	err := r.db.QueryRow(ctx,
		`select U.id, U.login, U.password, UP.name, UP.bio, UP.salary
		from "user" U join user_profile UP on U.id = UP.user_id
		where U.login=$1`,
		login,
	).Scan(&user.ID, &user.Login, &user.Password, &user.Name, &user.Bio, &user.Salary)
	if err != nil {
		return nil, err
	}

	// Загружаем роли через общий метод
	roles, err := r.loadRoles(ctx, user.ID)
	if err != nil {
		return nil, err
	}
	user.Roles = roles
	return &user, nil
}

// FindByID находит пользователя по ID и загружает его роли
func (r *UserRepository) FindByID(id int) (*domain.User, error) {
	ctx := context.Background()
	var user domain.User
	// Получаем базовые поля: ID, login, password, имя и биографию
	err := r.db.QueryRow(ctx,
		`select U.id, U.login, U.password, UP.name, UP.bio, UP.salary
		from "user" U join user_profile UP on U.id = UP.user_id
		where U.id=$1`,
		id,
	).Scan(&user.ID, &user.Login, &user.Password, &user.Name, &user.Bio, &user.Salary)
	if err != nil {
		return nil, err
	}

	// Загружаем роли через общий метод
	roles, err := r.loadRoles(ctx, user.ID)
	if err != nil {
		return nil, err
	}
	user.Roles = roles
	return &user, nil
}

// CreateUser создаёт нового пользователя и возвращает его ID
func (r *UserRepository) CreateUser(u *domain.User) (int, error) {
	var id int
	err := r.db.QueryRow(context.Background(),
		`INSERT INTO "user" (login,password) VALUES ($1,$2) RETURNING id`,
		u.Login, u.Password,
	).Scan(&id)
	return id, err
}

// CreateProfile сохраняет профиль пользователя
func (r *UserRepository) CreateProfile(p *domain.UserProfile) error {
	_, err := r.db.Exec(context.Background(),
		`INSERT INTO user_profile (user_id,name,bio,salary) VALUES ($1,$2,$3,$4)`,
		p.UserID, p.Name, p.Bio, p.Salary,
	)
	return err
}

// AssignRoles назначает роли пользователю
func (r *UserRepository) AssignRoles(userID int, roleIDs []int) error {
	ctx := context.Background()
	for _, rid := range roleIDs {
		if _, err := r.db.Exec(ctx,
			`INSERT INTO users_roles (user_id, role_id) VALUES ($1,$2)`,
			userID, rid,
		); err != nil {
			return err
		}
	}
	return nil
}

// ValidateRoles проверяет, что все roleIDs существуют в таблице role
func (r *UserRepository) ValidateRoles(roleIDs []int) error {
	ctx := context.Background()
	// считаем, сколько ролей с такими ID есть в БД
	var count int
	err := r.db.QueryRow(ctx,
		`SELECT COUNT(*) FROM role WHERE id = ANY($1)`,
		roleIDs,
	).Scan(&count)
	if err != nil {
		return err
	}
	if count != len(roleIDs) {
		return domain.ErrRoleNotFound
	}
	return nil
}
