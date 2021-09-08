package setting

import (
	"encoding/json"
	"io/ioutil"

	"github.com/dwnGnL/testHandler/models"

	log "github.com/sirupsen/logrus"
)

var Config models.Config

func Setup(F string) {
	byteValue, err := ioutil.ReadFile(F)
	if err != nil {
		log.Fatalf("%v", err)
		return
	}

	err = json.Unmarshal(byteValue, &Config)

	if (models.CaptchaStruct{}) == Config.Captcha {
		log.Fatal("Captcha Struct cannot be empty")
	}

	//fmt.Println(Config)
	if err != nil {
		log.Fatalf("%v", err)
		return
	}
}
