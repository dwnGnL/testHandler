package db

import (
	"github.com/dwnGnL/testHandler/models"
	"github.com/dwnGnL/testHandler/pkg/pretty"
	"github.com/dwnGnL/testHandler/pkg/setting"
	"github.com/dwnGnL/testHandler/pkg/utils"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

var db *gorm.DB

// Setup initializes the database instance
func Setup() {
	var err error

	db, err = gorm.Open(postgres.Open(setting.Config.DB), &gorm.Config{Logger: logger.Default.LogMode(logger.Info)})

	if err != nil {
		pretty.LoglnFatal("db.Setup err:", err)
	}
	sqlDB, _ := db.DB()
	sqlDB.SetMaxOpenConns(100)

	//AutoMigrate
	autoMigrate()
	pretty.Logln("DB successfully connected! ")

	// if err := db.Set("gorm:query_option", "FOR UPDATE SKIP LOCKED").Model(&models.Payment{}).Where("status = ?", statuses.Processing).UpdateColumn("status", statuses.NeedPostCheck).Error; err != nil {
	// 	pretty.LoglnWarn("[awakeDeadProcessingPaymentsStatus]: ", err)
	// } //TODO:Wake Up sleep Payment

}

// CloseDB closes database connection (unnecessary)
func CloseDB() {
	sqlDB, err := db.DB()
	sqlDB.Close()
	if err != nil {
		pretty.Logln("Error on closing the DB: ", err)
	}
}

func GetDB() *gorm.DB {
	return db
}

func autoMigrate() {
	for _, model := range []interface{}{
		(*models.TUser)(nil),
		(*models.TokenEntity)(nil),
		(*models.Payment)(nil),
		(*models.Wallet)(nil),
	} {
		dbSilent := db.Session(&gorm.Session{Logger: logger.Default.LogMode(logger.Silent)})
		err := dbSilent.AutoMigrate(model)
		if err != nil {
			pretty.LoglnFatal("create model %s : %s", model, err)
		}
	}
	createAdmin()
}

func createAdmin() {
	var user models.TUser

	user.Salt, user.Password = utils.HashPassword("admin")

	var count int64
	db.Model(models.TUser{}).Where("login = ?", "admin").Count(&count)
	if count > 0 {
		return
	}
	user.IsAdmin = true
	user.Login = "admin"

	err := db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Create(&user).Error; err != nil {
			return err
		}
		if err := tx.Model(models.Wallet{}).Create(&models.Wallet{UserID: user.ID, Balance: 8, Currency: "USD"}).Error; err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		pretty.LoglnWarn(err.Error())
	}
}
