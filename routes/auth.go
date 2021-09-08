package routes

import (
	"crypto/sha512"
	"encoding/base64"
	"time"

	"github.com/dwnGnL/testHandler/models"

	"github.com/gin-gonic/gin"
)

func authenticate(login string, password string, c *gin.Context) (string, bool) {
	var user models.TUser

	if result := DB.Where("login = ?", login).Find(&user).Limit(1); result.Error == nil {
		if checkPasswordHash(password, user.Salt, user.Password) {
			now := time.Now()
			DB.Model(&user).UpdateColumn("login_at", now)
			return login, true
		}
	}

	return "", false
}

func payload(login string) map[string]interface{} {
	var user models.TUser

	if err := DB.Where("login = ? ", login).Find(&user); err.Error != nil {
		return map[string]interface{}{
			"userID":   0,
			"is_admin": "undefined",
			"userName": "0",
		}
	}

	// DB.Model().Update().Error

	return map[string]interface{}{
		"user_id":  user.ID,
		"is_admin": user.IsAdmin,
		"userName": user.Login,
		"fio":      user.FIO,
	}
}

func checkPasswordHash(password, salt, hash string) bool {

	var array []byte
	sha512h := sha512.New()

	array = append(array, []byte(password)...)
	array = append(array, []byte(salt)...)

	sha512h.Write(array)

	if base64.RawStdEncoding.EncodeToString(sha512h.Sum(nil)) == hash {
		return true
	}
	return false
}
