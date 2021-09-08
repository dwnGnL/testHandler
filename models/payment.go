package models

type Payment struct {
	ID            int64   `gorm:"column:id;primary_key"`
	UserID        int64   `gorm:"column:user_id"`
	User          TUser   `gorm:"foreignKey:UserID"`
	Amount        float64 `gorm:"column:amount;type:numeric(15,2)"`
	BalanceBefore float64 `gorm:"column:balance_before;type:numeric(15,2)"`
	BalanceAfter  float64 `gorm:"column:balance_after;type:numeric(15,2)"`
}
