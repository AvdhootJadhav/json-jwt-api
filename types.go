package main

import (
	"math/rand"
	"time"

	"golang.org/x/crypto/bcrypt"
)

type TransferRequest struct {
	ToAccount int `json:"toAccount"`
	Amount    int `json:"amount"`
}

type Account struct {
	ID                int       `json:"id"`
	FirstName         string    `json:"firstName"`
	LastName          string    `json:"lastName"`
	Number            int64     `json:"number"`
	Balance           int64     `json:"balance"`
	EncryptedPassword string    `json:"-"`
	CreatedAt         time.Time `json:"createdAt"`
}

type CreateAccountRequest struct {
	FirstName string `json:"firstName"`
	LastName  string `json:"lastName"`
	Password  string `json:"password"`
}

type LoginResponse struct {
	Number int64  `json:"number"`
	Token  string `json:"token"`
}

type LoginRequest struct {
	Number   int64  `json:"number"`
	Password string `json:"password"`
}

func NewAccount(firstName, lastName, password string) (*Account, error) {
	encpw, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)

	if err != nil {
		return nil, err
	}

	return &Account{
		FirstName:         firstName,
		LastName:          lastName,
		CreatedAt:         time.Now().UTC(),
		Number:            int64(rand.Intn(10000)),
		EncryptedPassword: string(encpw),
	}, nil
}

func (acc *Account) ValidatePassword(password string) bool {
	return bcrypt.CompareHashAndPassword([]byte(acc.EncryptedPassword), []byte(password)) == nil
}
