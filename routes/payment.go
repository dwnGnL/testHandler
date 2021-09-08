package routes

import (
	"errors"
	"net/http"

	"github.com/dwnGnL/testHandler/models"
	"github.com/dwnGnL/testHandler/pkg/e"
	"github.com/dwnGnL/testHandler/routes/middleware"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

///---------------------------------------------------------------------------------------------------------------------Make Payment
func Payment(c *gin.Context) {
	user := middleware.GetUserFromContext(c)
	err := DB.Transaction(func(tx *gorm.DB) error {
		var userDB models.TUser
		if err := tx.Preload("Wallet").Find(&userDB, user.UserID).Error; err != nil {
			return err
		}
		if userDB.Wallet.Balance < 1.1 {
			return errors.New("user balance less than necessary")
		}
		if err := tx.Model(models.Wallet{}).Where("user_id = ?", user.UserID).Update("balance", gorm.Expr("balance - ?", 1.1)).Error; err != nil {
			return err
		}
		var balance models.Wallet
		if err := tx.Where("user_id = ?", user.UserID).Find(&balance).Error; err != nil {
			return err
		}
		payment := models.Payment{
			UserID:        user.UserID,
			Amount:        1.1,
			BalanceBefore: userDB.Wallet.Balance,
			BalanceAfter:  balance.Balance,
		}
		if err := tx.Create(&payment).Error; err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		e.With(err).Write(c)
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "success"})
}
