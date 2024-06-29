package main

import (
	"database/sql"
	"fmt"

	_ "github.com/lib/pq"
)

type Storage interface {
	CreateAccount(*Account) error
	DeleteAccount(int) error
	UpdateAccount(*Account) error
	GetAccount(int) (*Account, error)
	GetAccounts() ([]*Account, error)
	GetAccountByNumber(int) (*Account, error)
}

type PostgresStore struct {
	db *sql.DB
}

func NewPostgresStore() (*PostgresStore, error) {
	connStr := "user=postgres password=root dbname=experiments sslmode=disable"
	db, err := sql.Open("postgres", connStr)

	if err != nil {
		return nil, err
	}

	if err := db.Ping(); err != nil {
		return nil, err
	}

	return &PostgresStore{db: db}, nil
}

func (s *PostgresStore) Init() error {
	return s.createAccountTable()
}

func (s *PostgresStore) createAccountTable() error {
	_, err := s.db.Exec("create table if not exists account (id serial primary key, first_name varchar, last_name varchar, number serial, balance serial, created_at timestamp, encrypted_password varchar)")

	if err != nil {
		return err
	}

	return nil
}

func (s *PostgresStore) GetAccountByNumber(number int) (*Account, error) {
	rows, err := s.db.Query("select * from account where number = $1", number)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		return scanIntoAccount(rows)
	}
	return nil, fmt.Errorf("account with number %d not found", number)

}

func (s *PostgresStore) CreateAccount(account *Account) error {
	_, err := s.db.Exec("insert into account(first_name, last_name, balance, created_at, number, encrypted_password) values ($1, $2, $3, $4, $5, $6)", &account.FirstName, &account.LastName, &account.Balance, &account.CreatedAt, &account.Number, &account.EncryptedPassword)
	if err != nil {
		return err
	}
	return nil
}

func (s *PostgresStore) UpdateAccount(*Account) error {
	return nil
}

func (s *PostgresStore) DeleteAccount(id int) error {
	_, err := s.db.Exec("delete from account where id = $1", id)

	if err != nil {
		return err
	}

	return nil
}

func (s *PostgresStore) GetAccount(id int) (*Account, error) {
	rows, err := s.db.Query("select * from account where id = $1", id)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		return scanIntoAccount(rows)
	}
	return nil, fmt.Errorf("account with id %d not found", id)
}

func (s *PostgresStore) GetAccounts() ([]*Account, error) {
	resp, err := s.db.Query("select * from account")

	if err != nil {
		return nil, err
	}

	accounts := []*Account{}

	for resp.Next() {
		account, err := scanIntoAccount(resp)
		if err != nil {
			return nil, err
		}
		accounts = append(accounts, account)
	}
	return accounts, nil
}

func scanIntoAccount(rows *sql.Rows) (*Account, error) {
	account := new(Account)
	err := rows.Scan(&account.ID, &account.FirstName, &account.LastName, &account.Number, &account.Balance, &account.CreatedAt, &account.EncryptedPassword)
	return account, err
}
