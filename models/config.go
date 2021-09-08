package models

type Config struct {
	AppConf App           `json:"app"`
	DB      string        `json:"db"`
	Cache   CacheStruct   `json:"cache"`
	Captcha CaptchaStruct `json:"captcha"`
}

type CaptchaStruct struct {
	Font       string `json:"font"`
	Enable     bool   `json:"enable"`
	ShowCnt    int    `json:"show_cnt"`
	ExpSeconds int    `json:"exp_seconds"`
}

type App struct {
	ServerName        string `json:"serverName"`
	Port              int64  `json:"portRun"`
	AccessTknTimeout  int64  `json:"accessTknTimeout"`
	RefreshTknTimeout int64  `json:"refreshTknTimeout"`
	Realm             string `json:"realm"`
	Debug             bool   `json:"debug"`
	AccessKey         string `json:"access_key"`
	RefreshKey        string `json:"refresh_key"`
}

type CacheStruct struct {
	EqualRequestTime EqualReq `json:"equal_requests_time"`
	LessRequestTime  LessReq  `json:"less_requests_time"`
	CleaningTime     int64    `json:"cleaning_time_seconds"`
	CheckingTIme     int64    `json:"checking_time_seconds"`
	WaitTime         int64    `json:"wait_time_seconds"`
}

type EqualReq struct {
	MaxRepeat int64 `json:"max_repeating"`
}

type LessReq struct {
	MaxRepeat int64 `json:"max_repeating"`
	Duration  int64 `json:"duration_seconds"`
}
