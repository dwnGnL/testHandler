package routes

import (
	"errors"
	"net/http"
	"strings"

	"github.com/dwnGnL/testHandler/models"
	"github.com/dwnGnL/testHandler/pkg/e"
	"github.com/dwnGnL/testHandler/pkg/pretty"
	"github.com/dwnGnL/testHandler/pkg/utils"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

func CreateUser(c *gin.Context) {
	var userReq models.TUser

	if err := c.ShouldBindJSON(&userReq); err != nil {
		e.With(err).Write(c)
		return
	}
	pretty.Logln(userReq)

	userReq.Login = strings.TrimSpace(userReq.Login)
	userReq.Login = strings.ToLower(userReq.Login)

	if ok := utils.ValidateUserStr(userReq.Login, 4, 20); !ok {
		e.With(errors.New("длина логина должна быть не менее 4 и не более 20 символов. Логин не должен содержать кириллицу")).Write(c)
		return
	}

	if ok := utils.ValidateUserStr(userReq.Password, 8, 20); !ok {
		e.With(errors.New("длина пароля должна быть не менее 8 и не более 20 символов. Пароль не должен содержать кириллицу")).Write(c)
		return
	}

	userReq.Salt, userReq.Password = utils.HashPassword(userReq.Password)

	var count int64
	DB.Model(models.TUser{}).Where("login = ?", userReq.Login).Count(&count)
	if count > 0 {
		e.With(errors.New("пользователь с таким логином уже создан")).Write(c)
		return
	}
	err := DB.Transaction(func(tx *gorm.DB) error {
		if err := tx.Create(&userReq).Error; err != nil {
			return err
		}
		if err := tx.Model(models.Wallet{}).Create(&models.Wallet{UserID: userReq.ID, Balance: 8, Currency: USD}).Error; err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		e.With(err).Write(c)
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Пользователь успешно создан"})
	return
}
