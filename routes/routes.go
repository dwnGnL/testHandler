package routes

import (
	"errors"
	"net/http"
	"sync"
	"time"

	"github.com/dwnGnL/testHandler/db"
	"github.com/dwnGnL/testHandler/pkg/e"
	log "github.com/dwnGnL/testHandler/pkg/logging"
	"github.com/dwnGnL/testHandler/pkg/setting"
	"github.com/dwnGnL/testHandler/routes/middleware"
	_ "github.com/julienschmidt/httprouter"
	"github.com/patrickmn/go-cache"

	"github.com/gin-gonic/gin"
	logrus "github.com/sirupsen/logrus"
)

var wg *sync.WaitGroup

func Setup(wgr *sync.WaitGroup) {
	wg = wgr
}

func Init() *gin.Engine {
	// Gettig url of DB
	DB = db.GetDB()
	middleware.Cache = cache.New(10*time.Second, -1)
	middleware.CaptchaShow = setting.Config.Captcha.ShowCnt

	// Loggin the gorm works
	logrus.SetOutput(gin.DefaultWriter)
	logger := logrus.New()
	logger.Level = logrus.TraceLevel
	logger.SetOutput(gin.DefaultWriter)

	// configuring jwt tokenSetupTerminalWorker
	jwtMiddleware := &middleware.GinJWTMiddleware{
		Realm:          setting.Config.AppConf.Realm,
		AccessKey:      []byte(setting.Config.AppConf.AccessKey),
		RefreshKey:     []byte(setting.Config.AppConf.RefreshKey),
		AccessTimeout:  time.Second * time.Duration(setting.Config.AppConf.AccessTknTimeout),
		RefreshTimeout: time.Second * time.Duration(setting.Config.AppConf.RefreshTknTimeout),
		MaxRefresh:     time.Hour * 24,
		Authenticator:  authenticate,
		PayloadFunc:    payload,
		Authorizator:   middleware.Authenticator,
		DB:             db.GetDB(),
	}

	// Initialize default gin router
	defaultRouter := gin.Default()

	defaultRouter.Use(log.Logger(logger), gin.Recovery())
	defaultRouter.Use(middleware.CORSMiddleware())
	defaultRouter.POST("/login", jwtMiddleware.LoginHandler)
	defaultRouter.GET("/refresh", jwtMiddleware.RefreshToken)

	defaultRouter.Use(jwtMiddleware.MiddlewareFunc())
	{
		defaultRouter.DELETE("/logout", jwtMiddleware.LogOut)

		defaultRouter.POST("/users", AccessForAdmin(CreateUser))

		defaultRouter.POST("/payment", Payment)

	}

	defaultRouter.NoRoute(func(c *gin.Context) {
		c.JSON(http.StatusNotFound, gin.H{"code": "PAGE_NOT_FOUND", "message": "Page not found"})
	})
	return defaultRouter
}

func AccessForAdmin(f funcGin) gin.HandlerFunc {
	return func(c *gin.Context) {
		user := middleware.GetUserFromContext(c)

		if user.IsAdmin {
			f(c)
			return
		}

		e.With(errors.New("доступ запрещен")).Write(c)
	}
}
