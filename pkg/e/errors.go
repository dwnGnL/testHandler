package e

import (
	"fmt"
	"net"
	"net/http"

	"github.com/dwnGnL/testHandler/pkg/pretty"

	"github.com/getsentry/sentry-go"
	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator"
	"github.com/iancoleman/strcase"
	"gorm.io/gorm"

	"github.com/dwnGnL/testHandler/pkg/setting"
	"github.com/dwnGnL/testHandler/pkg/types"
)

type Writer interface {
	Write(ctx *gin.Context)
}

type Type string

const (
	ErrInternal              Type = "Внутренняя ошибка"
	ErrNotFound              Type = "Не найдено"
	ErrPermission            Type = "Отсутствуют права на операцию"
	ErrEditPermission        Type = "Редактирование утвержденной записи невозможно"
	ErrPublishPermission     Type = "Отсутствуют права на публикацию"
	ErrCookie                Type = "Отсутствуют необходимые cookie"
	ErrCookieValue           Type = "Неверные данные cookie"
	ErrCookieCreate          Type = "Ошибка создания cookie"
	ErrDifferentParams       Type = "Данные не совпадают"
	ErrEmptyValue            Type = "Пустое значение"
	ErrEmptyRequiredField    Type = "Отсутствуют обязательные поля"
	ErrMissingParameters     Type = "Отсутствуют обязательные параметры"
	ErrWrongTypeValue        Type = "Неверный тип значения"
	ErrCaptchaVerification   Type = "Невалидная капча"
	ErrAgreeConfirm          Type = "Подтвердите свое согласие"
	ErrMailSend              Type = "Ошибка отправки почты"
	ErrSMSSend               Type = "Ошибка отправки смс"
	ErrValue                 Type = "Ошибка в значениях"
	ErrValueTimeFormat       Type = "Неверный формат даты"
	ErrOops                  Type = "Что то пошло не так"
	ErrTokenHeaderMissing    Type = "Отсутствуют необходимые заголовки"
	ErrTokenEmpty            Type = "Отсутствует или неверный токен"
	ErrStagePermission       Type = "Неизвестный сценарий пользователя"
	ErrValidation            Type = "Ошибка валидации"
	ErrUnique                Type = "Ошибка уникальности данных"
	ErrEncryptDecrypt        Type = "Ошибка шифрования"
	ErrExecQuery             Type = "Ошибка условий запроса"
	ErrNotImplemented        Type = "В процессе разработки"
	ErrPhoneNumberUnique     Type = "Номер уже занят"
	ErrPhoneNumberRegistered Type = "Номер уже зарегистрирован"
	ErrPhoneNumberConfirmed  Type = "Номер уже подтвержден"
	ErrPhoneNumberCodeSend   Type = "Код подтверждения уже выслан"
	ErrIsPDFFile             Type = "Один или несколько файлов являются .pdf"
	ErrTemplateExecute       Type = "Операция с шаблоном завершилась с ошибкой"
	ErrAlreadyUsing          Type = "Уже используется"
	ErrDateFormat            Type = "Не верный формат даты"
	ErrNonActive             Type = "Более не активно"
	ErrNonActiveUser         Type = "Пользователь более не активен"
	ErrWrongCombination      Type = "Не верное сочетание"
	ErrUnknownInterface      Type = "Неподдерживаемый тип интерфейса"
	ErrSlowDown              Type = "Не так много запросов, пожалуйста"
	ErrTotalCountImages      Type = "Превышен лимит загружаемых фото"
	ErrEmptyRequiredHeader   Type = "Отсутствуют обязательные заголовки"
	ErrLastStatusIsSame      Type = "Последний такого типа уже существует"
	ErrEmptyResolution       Type = "Резолюция на отклонение обязательна"
	ErrUserAlreadyRegistered Type = "Пользователь уже зарегистрирован"
)

func (t Type) Error() string {
	return string(t)
}

func (t Type) String() string {
	return string(t)
}

func (t Type) Write(c *gin.Context) {
	e := _e{Type: t}
	t.WriteHubHeader(c)
	c.AbortWithStatusJSON(http.StatusBadRequest, e)

}

func (t Type) WriteHubHeader(c *gin.Context) {
	types.HttpHeaderErr.Set(t.String(), c)
}

type _e struct {
	Type      `json:"message"`
	ErrCode   ErrCode `json:"code,omitempty"`
	ErrField  string  `json:"field,omitempty"`
	ErrFields []Field `json:"fields,omitempty"`
	ErrDetail string  `json:"detail,omitempty"`
	xHeader   string
	xStatus   int
}

func (e _e) Error() string {
	return e.Type.Error()
}

// Code
// Set error code
func (e *_e) Code(code ErrCode) *_e {
	e.ErrCode = code
	return e
}

// Field
// Set field name
func (e *_e) Field(field string) *_e {
	e.ErrField = field
	return e
}

// Detail
// Set detail description
func (e *_e) Detail(text string) *_e {
	e.ErrDetail = text
	return e
}

// Status
// Set HTTP status
func (e *_e) Status(status int) *_e {
	e.xStatus = status
	return e
}

// Header
// Set detail header
func (e *_e) Header(mes string) *_e {
	e.xHeader = mes
	return e
}

// Write to response
func (e *_e) Write(c *gin.Context) {
	if e.xStatus < http.StatusOK {
		e.xStatus = http.StatusBadRequest
	}
	// если дебаг то пишем в HubErrDetailHeader хедер детализацию ошибки
	if setting.Config.AppConf.Debug {
		types.HttpHeaderErrDetail.Set(e.xHeader, c)
	}
	types.HttpHeaderErr.Set(e.String(), c)
	ev := sentry.NewEvent()
	if c.Request != nil {
		ev.Contexts["url"] = c.Request.URL.String()
		ev.Tags["url"] = c.Request.URL.String()
	}
	ev.Extra["detail"] = e.ErrDetail
	ev.Extra["field"] = e.ErrField
	ev.Extra["fields"] = e.ErrFields
	ev.Extra["xHeader"] = e.xHeader
	ev.Level = sentry.LevelInfo
	ev.Message = fmt.Sprintf("%s %s", e.String(), e.xHeader)
	go func(event *sentry.Event) {
		sentry.CaptureEvent(event)
	}(ev)
	c.AbortWithStatusJSON(e.xStatus, &e)
}

// With
// Common error response constructor
func With(err error) *_e {
	msg := err.Error()
	pretty.LoglnWarn(msg)
	statusCode := http.StatusBadRequest
	xHeader := ""
	// if v, ok := err.(); ok {
	// 	msg = errorCodeNames[v.Field('C')]
	// 	xHeader = err.Error()
	// }
	if err == gorm.ErrRecordNotFound {
		statusCode = http.StatusNotFound
		msg = ErrNotFound.Error()
	}

	if err == ErrNotFound {
		statusCode = http.StatusNotFound
	}
	if _, ok := err.(net.Error); ok {
		msg = "Timeout error"
	}
	if err == http.ErrNoCookie {
		msg = ErrCookie.String()
		xHeader = err.Error()
	}

	var fields []Field
	if v, ok := err.(validator.ValidationErrors); ok {
		msg = ErrValidation.String()
		xHeader = err.Error()
		for _, key := range v {
			detail := Field{
				Name: strcase.ToSnake(key.Field()),
				Tag:  key.ActualTag(),
			}
			fields = append(fields, detail)
		}
	}

	t := Type(msg)
	ee := _e{Type: t, xHeader: xHeader, xStatus: statusCode}
	if len(fields) > 0 {
		ee.ErrFields = fields
	}
	if v, ok := err.(ErrCode); ok {
		ee.ErrCode = v
	}
	return &ee
}
