package middleware

import (
	"errors"
	"fmt"
	"image/color"
	"image/png"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/afocus/captcha"
	"github.com/dgrijalva/jwt-go"
	"github.com/dwnGnL/testHandler/models"
	"github.com/dwnGnL/testHandler/pkg/e"
	"github.com/dwnGnL/testHandler/pkg/pretty"
	"github.com/dwnGnL/testHandler/pkg/setting"
	"github.com/gin-gonic/gin"
	gocache "github.com/patrickmn/go-cache"
	"gorm.io/gorm"
)

// GinJWTMiddleware provides a Json-Web-Token authentication implementation. On failure, a 401 HTTP response
// is returned. On success, the wrapped middleware is called, and the userID is made available as
// c.Get("userID").(string).
// Users can get a token by posting a json request to LoginHandler. The token then needs to be passed in
// the Authentication header. Example: Authorization:Bearer XXX_TOKEN_XXX
type GinJWTMiddleware struct {
	// Realm name to display to the user. Required.
	Realm string

	// signing algorithm - possible values are HS256, HS384, HS512
	// Optional, default is HS256.
	SigningAlgorithm string

	// Secret access token key used for signing. Required.
	AccessKey []byte

	// Secret refresh token key used for signing. Required.
	RefreshKey []byte

	// Duration that a jwt token is valid. Optional, defaults to one hour.
	AccessTimeout time.Duration

	// Duration that a refresh jwt token is valid.
	RefreshTimeout time.Duration

	// This field allows clients to refresh their token until MaxRefresh has passed.
	// Note that clients can refresh their token in the last moment of MaxRefresh.
	// This means that the maximum validity timespan for a token is MaxRefresh + Timeout.
	// Optional, defaults to 0 meaning not refreshable.
	MaxRefresh time.Duration

	// Callback function that should perform the authentication of the user based on userID and
	// password. Must return true on success, false on failure. Required.
	// Option return user id, if so, user id will be stored in Claim Array.
	Authenticator func(userID string, password string, c *gin.Context) (string, bool)

	// Callback function that should perform the authorization of the authenticated user. Called
	// only after an authentication success. Must return true on success, false on failure.
	// Optional, default to success.
	Authorizator func(userID string, c *gin.Context) (string, bool)

	// Callback function that will be called during login.
	// Using this function it is possible to add additional payload data to the webtoken.
	// The data is then made available during requests via c.Get("JWT_PAYLOAD").
	// Note that the payload is not encrypted.
	// The attributes mentioned on jwt.io can't be used as keys for the map.
	// Optional, by default no additional data will be set.
	PayloadFunc func(userID string) map[string]interface{}

	// User can define own Unauthorized func.
	Unauthorized func(*gin.Context, int, string)

	// Set the identity handler function
	IdentityHandler func(jwt.MapClaims) string

	// TokenLookup is a string in the form of "<source>:<name>" that is used
	// to extract token from the request.
	// Optional. Default value "header:Authorization".
	// Possible values:
	// - "header:<name>"
	// - "query:<name>"
	// - "cookie:<name>"
	TokenLookup string

	// TokenHeadName is a string in the header. Default value is "Bearer"
	TokenHeadName string

	// TimeFunc provides the current time. You can override it to use another time value. This is useful for testing or if your server uses a different time zone than your tokens.
	TimeFunc func() time.Time

	DB *gorm.DB
}

// Login form structure.
type Login struct {
	Username string `form:"username" json:"username" binding:"required"`
	Password string `form:"password" json:"password" binding:"required"`
	Captcha  string `form:"captcha" json:"captcha,omitempty"`
}

//Captcha
var Cache *gocache.Cache

var CaptchaShow int

type attempt struct {
	captcha  string
	failNum  int
	lastTime time.Time
}

// MiddlewareInit initialize jwt configs.
func (mw *GinJWTMiddleware) MiddlewareInit() error {

	if mw.TokenLookup == "" {
		mw.TokenLookup = "header:Authorization"
	}

	if mw.SigningAlgorithm == "" {
		mw.SigningAlgorithm = "HS256"
	}

	if mw.AccessTimeout == 0 {
		mw.AccessTimeout = time.Hour
	}

	if mw.RefreshTimeout == 0 {
		mw.RefreshTimeout = 24 * time.Hour
	}

	if mw.TimeFunc == nil {
		mw.TimeFunc = time.Now
	}

	mw.TokenHeadName = strings.TrimSpace(mw.TokenHeadName)
	if len(mw.TokenHeadName) == 0 {
		mw.TokenHeadName = "Bearer"
	}

	if mw.Authorizator == nil {
		mw.Authorizator = func(userID string, c *gin.Context) (string, bool) {
			return "", true
		}
	}

	if mw.Unauthorized == nil {
		mw.Unauthorized = func(c *gin.Context, code int, message string) {
			c.JSON(code, gin.H{
				"code":    code,
				"message": message,
			})
		}
	}

	if mw.IdentityHandler == nil {
		mw.IdentityHandler = func(claims jwt.MapClaims) string {
			return claims["login"].(string)
		}
	}

	if mw.Realm == "" {
		return errors.New("realm is required")
	}

	if mw.AccessKey == nil {
		return errors.New("secret key is required")
	}

	return nil
}

func GetUserFromContext(c *gin.Context) models.UserRole {
	claims := ExtractClaims(c)
	return models.UserRole{
		UserID:   int64(claims["user_id"].(float64)),
		UserName: claims["userName"].(string),
		IsAdmin:  claims["is_admin"].(bool),
	}
}

// MiddlewareFunc makes GinJWTMiddleware implement the Middleware interface.
func (mw *GinJWTMiddleware) MiddlewareFunc() gin.HandlerFunc {
	if err := mw.MiddlewareInit(); err != nil {
		return func(c *gin.Context) {
			mw.unauthorized(c, http.StatusInternalServerError, err.Error())
			return
		}
	}

	return func(c *gin.Context) {
		mw.middlewareImpl(c)
		return
	}
}

func (mw *GinJWTMiddleware) middlewareImpl(c *gin.Context) {
	token, err := mw.parseToken(c)

	if err != nil {
		mw.unauthorized(c, http.StatusUnauthorized, err.Error())
		return
	}

	claims := token.Claims.(jwt.MapClaims)

	id := mw.IdentityHandler(claims)
	c.Set("JWT_PAYLOAD", claims)
	c.Set("userID", id)

	if msg, ok := mw.Authorizator(id, c); !ok {
		mw.unauthorized(c, http.StatusForbidden, msg)
		return
	}

	c.Next()
}

//--Captcha--
func (mw *GinJWTMiddleware) sendCaptcha(c *gin.Context, userCache *attempt) {
	cap := captcha.New()

	if err := cap.SetFont(setting.Config.Captcha.Font); err != nil {
		panic(err.Error())
	}

	cap.SetSize(128, 54)
	cap.SetDisturbance(captcha.MEDIUM)
	cap.SetFrontColor(color.RGBA{0, 0, 0, 191})
	cap.SetBkgColor(color.RGBA{232, 232, 232, 255})

	img, str := cap.Create(6, captcha.NUM)
	userCache.captcha = str
	fmt.Println("str: ", str)
	// saving captcha
	//ID_middleware.SetCaptcha(clientIP, str)
	c.Writer.WriteHeader(429)
	c.Writer.Header().Set("Content-Type", "image/png")
	err := png.Encode(c.Writer, img)

	if err != nil {
		log.Println("Write image error:", err.Error())
		return
	}

	return
}

// LoginHandler can be used by clients to get a jwt token.
// Payload needs to be json in the form of {"username": "USERNAME", "password": "PASSWORD"}.
// Reply will be of the form {"token": "TOKEN"}.
func (mw *GinJWTMiddleware) LoginHandler(c *gin.Context) {
	// Initial middleware default setting.
	_ = mw.MiddlewareInit()
	// c.Writer.Header().Set("Content-type")
	var loginVals Login
	var userCache *attempt

	if err := c.BindJSON(&loginVals); err != nil {
		mw.unauthorized(c, http.StatusBadRequest, "Missing Username or Password")
		return
	}

	if mw.Authenticator == nil {
		mw.unauthorized(c, http.StatusInternalServerError, "Missing define authenticator func")
		return
	}

	//--Captcha--
	ipAddress := ""
	fwdAddress := c.GetHeader("X-Forwarded-For") // capitalisation doesn't matter
	if fwdAddress != "" {
		// Got X-Forwarded-For
		ipAddress = fwdAddress // If it's a single IP, then awesome!

		// If we got an array... grab the first IP
		ips := strings.Split(fwdAddress, ", ")
		if len(ips) > 1 {
			ipAddress = ips[0]
		}
	}
	fmt.Println("clientIP:", ipAddress)
	fmt.Println("Header:", c.Request.Header)
	foo, found := Cache.Get(ipAddress)
	if found {
		userCache = foo.(*attempt)
	} else {
		userCache = &attempt{}
	}

	if !userCache.lastTime.IsZero() {
		diff := time.Now().Sub(userCache.lastTime)
		if diff >= time.Duration(setting.Config.Captcha.ExpSeconds)*time.Second && userCache.failNum < CaptchaShow {
			Cache.Delete(ipAddress)
			userCache = &attempt{}
		}
	}

	fmt.Println("userCache", *userCache)
	fmt.Println("captcha enable:", setting.Config.Captcha.Enable)
	//--Captcha--
	if userCache.failNum >= CaptchaShow && userCache.captcha != loginVals.Captcha {
		userCache.failNum += 1
		mw.sendCaptcha(c, userCache)
		Cache.Set(ipAddress, userCache, -1)
		return
	}

	_, ok := mw.Authenticator(loginVals.Username, loginVals.Password, c)

	if !ok {
		//--Captcha--
		if setting.Config.Captcha.Enable {
			userCache.failNum += 1
			if userCache.failNum >= CaptchaShow {
				mw.sendCaptcha(c, userCache)
			} else {
				userCache.lastTime = time.Now()
			}
			Cache.Set(ipAddress, userCache, -1)
		}
		mw.unauthorized(c, http.StatusUnauthorized, "Incorrect Username / Password")
		return
	}

	// Create the token
	err, tokenEntity := mw.updateToken(loginVals.Username, c.Request.UserAgent())
	if err != nil {
		mw.unauthorized(c, http.StatusUnauthorized, "Create JWT Token failed")
		return
	}

	Cache.Delete(ipAddress)

	c.JSON(http.StatusOK, gin.H{
		"login":          loginVals.Username,
		"access_token":   tokenEntity.AtToken,
		"refresh_token":  tokenEntity.RtToken,
		"access_expire":  tokenEntity.AtExpire.Format(time.RFC3339),
		"refresh_expire": tokenEntity.RtExpire.Format(time.RFC3339),
	})
}

type token struct {
	AtToken  string
	AtExpire time.Time
	RtToken  string
	RtExpire time.Time
}

func (mw *GinJWTMiddleware) deleteToken(userName string, userAgent string) error {
	var id int64
	if err := mw.DB.Model(&models.TUser{}).Where("login = ?", userName).Select("id").Scan(&id).Error; err != nil {
		return err
	}
	if err := mw.DB.Where("user_id = ? and user_agent = ?", id, userAgent).Delete(&models.TokenEntity{}).Error; err != nil {
		return err
	}
	return nil
}

func (mw *GinJWTMiddleware) updateToken(userName string, userAgent string) (error, token) {

	atToken := jwt.New(jwt.GetSigningMethod(mw.SigningAlgorithm))
	atClaims := atToken.Claims.(jwt.MapClaims)

	if mw.PayloadFunc != nil {
		for key, value := range mw.PayloadFunc(userName) {
			atClaims[key] = value
		}
	}

	atExpire := mw.TimeFunc().Add(mw.AccessTimeout)
	atClaims["login"] = userName
	atClaims["t_exp"] = atExpire.Unix()
	atClaims["orig_iat"] = mw.TimeFunc().Unix()

	accessToken, err := atToken.SignedString(mw.AccessKey)

	if err != nil {
		return err, token{}
	}

	var id int64
	if err := mw.DB.Model(&models.TUser{}).Where("login = ?", userName).Select("id").Scan(&id).Error; err != nil {
		return err, token{}
	}

	rtToken := jwt.New(jwt.GetSigningMethod(mw.SigningAlgorithm))
	rtClaims := rtToken.Claims.(jwt.MapClaims)

	rtExpire := mw.TimeFunc().Add(mw.RefreshTimeout)
	rtClaims["t_exp"] = rtExpire.Unix()
	rtClaims["orig_iat"] = mw.TimeFunc().Unix()
	rtClaims["login"] = userName
	rtClaims["userID"] = id

	refreshToken, err := rtToken.SignedString(mw.RefreshKey)
	if err != nil {
		pretty.Logln("error: can't create jwt token ")
		return err, token{}
	}
	err = mw.DB.Transaction(func(tx *gorm.DB) error {
		if err := tx.Model(&models.TUser{}).Where("id = ?", id).UpdateColumns(map[string]interface{}{
			"login_at": time.Now(),
		}).Error; err != nil {
			return err
		}
		var count int64
		if err := tx.Model(models.TokenEntity{}).Where("user_id = ? and user_agent = ?", id, userAgent).Count(&count).Error; err != nil {
			return err
		}
		if count != 0 {
			if err := tx.Model(models.TokenEntity{}).Where("user_id = ? and user_agent = ?", id, userAgent).Update("refresh_token", refreshToken).Error; err != nil {
				return err
			}
		} else {
			if err := tx.Create(&models.TokenEntity{UserID: id, RefreshToken: refreshToken, UserAgent: userAgent}).Error; err != nil {
				return err
			}
		}
		return nil
	})

	if err != nil {
		return err, token{}
	}
	return nil, token{
		AtToken:  accessToken,
		AtExpire: atExpire,
		RtToken:  refreshToken,
		RtExpire: rtExpire,
	}
}

// 18.08.2021 20:32:29;17.00;RUB;567450845 ;309465538;11120604;0.00;0.17

func (mw *GinJWTMiddleware) RefreshToken(c *gin.Context) {
	rtTokenReq, err := mw.jwtFromHeader(c, "Refresh-Authorization")

	if err != nil {
		e.With(err).Write(c)
		return
	}

	token, err := jwt.Parse(rtTokenReq, func(token *jwt.Token) (interface{}, error) {
		if jwt.GetSigningMethod(mw.SigningAlgorithm) != token.Method {
			return nil, errors.New("invalid signing algorithm")
		}

		return mw.RefreshKey, nil
	})

	if err != nil {
		pretty.Logln("error: signing algorigthm")
		e.With(err).Write(c)
		return
	}

	claims := token.Claims.(jwt.MapClaims)
	expire := int64(claims["t_exp"].(float64))
	userID := int64(claims["userID"].(float64))

	var user models.TUser
	if err := mw.DB.Where("id = ?", userID).Preload("Sessions", "user_agent = ?", c.Request.UserAgent()).Find(&user).Error; err != nil {
		e.With(err).Write(c)
		return
	}
	var userRtToken string
	if len(user.Sessions) > 0 {
		userRtToken = user.Sessions[0].RefreshToken
	}
	if rtTokenReq != userRtToken {
		pretty.Logln("error: tokens doesn't match")
		c.JSON(402, "incorrect token")
		return
	}

	if expire < mw.TimeFunc().Unix() {
		pretty.Logln("error: expired token")
		mw.unauthorized(c, 402, "token is expired")
		return
	}

	if _, ok := token.Claims.(jwt.Claims); !ok && !token.Valid {
		pretty.Logln("error: invalid token")
		c.JSON(402, err)
		return
	}

	// Create the token
	err, tokenEntity := mw.updateToken(user.Login, c.Request.UserAgent())
	if err != nil {
		mw.unauthorized(c, http.StatusUnauthorized, "Create JWT Token failed")
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"login":          user.Login,
		"access_token":   tokenEntity.AtToken,
		"refresh_token":  tokenEntity.RtToken,
		"access_expire":  tokenEntity.AtExpire.Format(time.RFC3339),
		"refresh_expire": tokenEntity.RtExpire.Format(time.RFC3339),
	})
}

// RefreshHandler can be used to refresh a token. The token still needs to be valid on refresh.
// Shall be put under an endpoint that is using the GinJWTMiddleware.
// Reply will be of the form {"token": "TOKEN"}.
func (mw *GinJWTMiddleware) RefreshHandler(c *gin.Context) {
	token, _ := mw.parseToken(c)
	claims := token.Claims.(jwt.MapClaims)

	origIat := int64(claims["orig_iat"].(float64))

	if origIat < mw.TimeFunc().Add(-mw.MaxRefresh).Unix() {
		mw.unauthorized(c, http.StatusUnauthorized, "Token is expired.")
		return
	}

	// Create the token
	newToken := jwt.New(jwt.GetSigningMethod(mw.SigningAlgorithm))
	newClaims := newToken.Claims.(jwt.MapClaims)

	for key := range claims {
		newClaims[key] = claims[key]
	}

	expire := mw.TimeFunc().Add(mw.AccessTimeout)
	newClaims["login"] = claims["login"]
	newClaims["exp"] = expire.Unix()
	newClaims["orig_iat"] = origIat

	tokenString, err := newToken.SignedString(mw.AccessKey)

	if err != nil {
		mw.unauthorized(c, http.StatusUnauthorized, "Create JWT Token faild")
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"token":  tokenString,
		"expire": expire.Format(time.RFC3339),
	})
}

// ExtractClaims help to extract the JWT claims
func ExtractClaims(c *gin.Context) jwt.MapClaims {

	if _, exists := c.Get("JWT_PAYLOAD"); !exists {
		emptyClaims := make(jwt.MapClaims)
		return emptyClaims
	}

	jwtClaims, _ := c.Get("JWT_PAYLOAD")

	return jwtClaims.(jwt.MapClaims)
}

// TokenGenerator handler that clients can use to get a jwt token.
func (mw *GinJWTMiddleware) TokenGenerator(userID string) string {
	token := jwt.New(jwt.GetSigningMethod(mw.SigningAlgorithm))
	claims := token.Claims.(jwt.MapClaims)

	if mw.PayloadFunc != nil {
		for key, value := range mw.PayloadFunc(userID) {
			claims[key] = value
		}
	}

	claims["login"] = userID
	claims["exp"] = mw.TimeFunc().Add(mw.AccessTimeout).Unix()
	claims["orig_iat"] = mw.TimeFunc().Unix()

	tokenString, _ := token.SignedString(mw.AccessKey)

	return tokenString
}

func (mw *GinJWTMiddleware) LogOut(c *gin.Context) {
	var userAgent string
	userAgent, exist := c.GetQuery("user_agent")
	if !exist {
		e.With(errors.New("user_agent is required")).Write(c)
		return
	}
	user := GetUserFromContext(c)

	if err := mw.deleteToken(user.UserName, userAgent); err != nil {
		e.With(err).Write(c)
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "success"})

}

func (mw *GinJWTMiddleware) jwtFromHeader(c *gin.Context, key string) (string, error) {
	authHeader := c.Request.Header.Get(key)

	if authHeader == "" {
		return "", errors.New("auth header empty")
	}

	parts := strings.SplitN(authHeader, " ", 2)
	if !(len(parts) == 2 && parts[0] == mw.TokenHeadName) {
		return "", errors.New("invalid auth header")
	}

	return parts[1], nil
}

func (mw *GinJWTMiddleware) jwtFromQuery(c *gin.Context, key string) (string, error) {
	token := c.Query(key)

	if token == "" {
		return "", errors.New("Query token empty")
	}

	return token, nil
}

func (mw *GinJWTMiddleware) jwtFromCookie(c *gin.Context, key string) (string, error) {
	cookie, _ := c.Cookie(key)

	if cookie == "" {
		return "", errors.New("Cookie token empty")
	}

	return cookie, nil
}

func (mw *GinJWTMiddleware) parseToken(c *gin.Context) (*jwt.Token, error) {
	var tokenStr string
	var err error

	parts := strings.Split(mw.TokenLookup, ":")
	switch parts[0] {
	case "header":
		tokenStr, err = mw.jwtFromHeader(c, parts[1])
	case "query":
		tokenStr, err = mw.jwtFromQuery(c, parts[1])
	case "cookie":
		tokenStr, err = mw.jwtFromCookie(c, parts[1])
	}

	if err != nil {
		return nil, err
	}

	token, err := jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
		if jwt.GetSigningMethod(mw.SigningAlgorithm) != token.Method {
			return nil, errors.New("invalid signing algorithm")
		}

		return mw.AccessKey, nil
	})

	if err != nil {
		return nil, err
	}

	claims := token.Claims.(jwt.MapClaims)
	expire := int64(claims["t_exp"].(float64))

	if expire < mw.TimeFunc().Unix() {
		return nil, errors.New("token is expired")
	}

	return token, err
}

func (mw *GinJWTMiddleware) unauthorized(c *gin.Context, code int, message string) {

	if mw.Realm == "" {
		mw.Realm = "gin jwt"
	}

	c.Header("WWW-Authenticate", "JWT realm="+mw.Realm)
	c.Abort()

	mw.Unauthorized(c, code, message)

	return
}

//CORSMiddleware solve cors problem by adding headers
func CORSMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Writer.Header().Set("Content-Type", "application/json")
		c.Writer.Header().Set("Access-Control-Allow-Origin", "*")
		c.Writer.Header().Set("Access-Control-Allow-Methods", "GET,PUT,POST,DELETE")
		c.Writer.Header().Set("Access-Control-Allow-Credentials", "true")
		c.Writer.Header().Set("Access-Control-Allow-Headers", "Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization, Refresh-Authorization")

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(200)
		}

		c.Next()
	}
}

///---------------------------------------------------------------------------------------------------------------------Perebor

var cache *gocache.Cache

func init() {
	cache = gocache.New(
		time.Second*time.Duration(setting.Config.Cache.CleaningTime),
		time.Second*time.Duration(setting.Config.Cache.CheckingTIme),
	)
}

type SslHeader struct {
	Header    string
	arrayData *[]string
}

func (s *SslHeader) GetValue(value string) *string {
	if s.Header == "" {
		return nil
	}
	if s.arrayData == nil {
		arr := strings.Split(s.Header, ",")
		s.arrayData = &arr
	}
	for _, data := range *s.arrayData {
		arryS := strings.Split(data, "=")
		if arryS[0] == value {
			if arryS[1] != "" {
				return &arryS[1]
			}
		}
	}
	return nil
}

type bodyCache struct {
	LastTime  time.Time
	CountTime int64
}

type keyCache struct {
	Maps     map[string]bodyCache
	RuleTime *time.Time
	DiffTime time.Duration
	CountDur int64
	LastTime time.Time
}

func Authenticator(login string, c *gin.Context) (string, bool) {
	ipAddress := ""
	fwdAddress := c.GetHeader("X-Forwarded-For") // capitalisation doesn't matter
	if fwdAddress != "" {
		// Got X-Forwarded-For
		ipAddress = fwdAddress // If it's a single IP, then awesome!

		// If we got an array... grab the first IP
		ips := strings.Split(fwdAddress, ", ")
		if len(ips) > 1 {
			ipAddress = ips[0]
		}
	}
	route := c.FullPath() + c.Request.Method
	key := login + ipAddress

	if item, has := cache.Get(key); has {
		if client, ok := item.(keyCache); ok {

			/// --------------------------------------------------------------------------------------------------------CheckForStop
			/// Check for RuleTIME
			if client.RuleTime != nil {
				/// wait for ending ruleTime
				if time.Now().Before(*client.RuleTime) {
					msg := fmt.Sprintf("Следующая попыка возможна через %d сек.", int64((*client.RuleTime).Sub(time.Now()).Seconds()))
					return msg, false
				}
				/// new note for current client
				client.RuleTime = nil
				client.DiffTime = 0
				client.CountDur = 1
				client.LastTime = time.Now()
				client.Maps[route] = bodyCache{LastTime: time.Now(), CountTime: 1}
				cache.Set(key, client, gocache.DefaultExpiration)
				return "", true
			}

			waitTime := setting.Config.Cache.WaitTime

			/// Check for time which less than 5 seconds
			lessMax := setting.Config.Cache.LessRequestTime.MaxRepeat
			lessDur := setting.Config.Cache.LessRequestTime.Duration

			if client.Maps[route].CountTime >= lessMax &&
				time.Now().Before(client.Maps[route].LastTime.Add(time.Second*time.Duration(lessDur))) {
				/// new note for current client
				tm := time.Now().Add(time.Second * time.Duration(waitTime))
				client.RuleTime = &tm
				client.DiffTime = 0
				client.CountDur = 1
				client.LastTime = time.Now()
				client.Maps[route] = bodyCache{LastTime: time.Now(), CountTime: 1}

				msg := fmt.Sprintf("Следующая попыка возможна через %d сек.", waitTime)
				cache.Set(key, client, gocache.DefaultExpiration)
				return msg, false
			}

			/// Check for time which repeats more than 5 times
			equalMax := setting.Config.Cache.EqualRequestTime.MaxRepeat

			if client.CountDur >= equalMax && int64(time.Now().Sub(client.LastTime).Seconds()) == int64(client.DiffTime.Seconds()) {
				/// new note for current client
				tm := time.Now().Add(time.Second * time.Duration(waitTime))
				client.RuleTime = &tm
				client.DiffTime = 0
				client.CountDur = 1
				client.Maps[route] = bodyCache{
					LastTime:  time.Now(),
					CountTime: 1,
				}

				msg := fmt.Sprintf("Следующая попыка возможна через %d сек.", waitTime)
				cache.Set(key, client, gocache.DefaultExpiration)
				return msg, false
			}

			/// --------------------------------------------------------------------------------------------------------SetNewRule
			/// Check for time which less than 5 seconds
			body := client.Maps[route]
			if time.Now().Before(client.Maps[route].LastTime.Add(time.Second * time.Duration(lessDur))) {
				body.CountTime++
			} else {
				body.CountTime = 0
			}
			body.LastTime = time.Now()

			/// Check for time which repeats more than 5 times
			if client.CountDur == 1 {
				client.DiffTime = time.Now().Sub(client.LastTime)
				client.CountDur++
			} else if int64(time.Now().Sub(client.LastTime).Seconds()) == int64(client.DiffTime.Seconds()) {
				client.CountDur++
			} else {
				client.CountDur = 1
			}
			client.LastTime = time.Now()

			/// --------------------------------------------------------------------------------------------------------SetNewRuleCache
			client.Maps[route] = body
			cache.Set(key, client, gocache.DefaultExpiration)
			return "", true
		} else {
			return fmt.Sprint("Cache problem items:", item.(keyCache)), false
		}
	} else {
		body := make(map[string]bodyCache)
		body[route] = bodyCache{
			LastTime:  time.Now(),
			CountTime: 1,
		}
		client := keyCache{Maps: body, RuleTime: nil, LastTime: time.Now(), DiffTime: 0, CountDur: 1}
		cache.Set(key, client, gocache.DefaultExpiration)
	}

	return "", true
}
