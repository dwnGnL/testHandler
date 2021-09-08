package models

import "time"

///---------------------------------------------------------USERS---------------------------------------------------------------------------------
type TUser struct {
	ID        int64          `json:"id" gorm:"column:id;primary_key;autoIncrement"`
	IsAdmin   bool           `json:"is_admin" gorm:"column:is_admin" validate:"gte=1"`
	FIO       string         `json:"fio" gorm:"column:fio;type:varchar(50)"`
	Login     string         `json:"login" gorm:"column:login;type:varchar(20)" validate:"gt=0"`
	Password  string         `json:"password" gorm:"column:password;type:varchar(200)" validate:"gt=0"`
	Salt      string         `json:"salt" gorm:"column:salt"`
	Sessions  []*TokenEntity `gorm:"foreignKey:UserID"`
	Wallet    Wallet         `gorm:"foreignKey:UserID"`
	CreatedAt *time.Time     `gorm:"autoCreateTime"`
	UpdatedAt *time.Time     `gorm:"autoUpdateTime"`
	LoginAt   *time.Time     `gorm:"column:login_at"`
}

type Wallet struct {
	UserID   int64   `gorm:"column:user_id"`
	Balance  float64 `gorm:"column:balance;type:numeric(15,2)"`
	Currency string  `gorm:"column:currecny"`
}

func (Wallet) TableName() string {
	return "wallet"
}

type TokenEntity struct {
	UserID       int64  `gorm:"column:user_id"`
	RefreshToken string `gorm:"column:refresh_token"`
	UserAgent    string `gorm:"column:user_agent"`
}

func (TokenEntity) TableName() string {
	return "tokens"
}

func (TUser) TableName() string {
	return "users"
}

type UserRole struct {
	UserName string // userName
	Role     string // roleName
	UserID   int64  // id
	IsAdmin  bool
}
