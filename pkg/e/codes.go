package e

type ErrCode uint16

const (
	ValueErrorCode ErrCode = iota + 1
	MissingParametersCode
	PermissionRequiredCode
	InternalErrorCode
	DBNotFoundCode
	CookieNotFoundCode
	UniqueFieldCode
	EmailWaitConfirmCode
	SMSTimeoutNeedCode
	AlreadyHasCode
	UnauthorizedCode = 401
)

func (c ErrCode) Error() string { // TODO: may be detach from error type?
	switch c {
	case ValueErrorCode:
		return ErrValue.Error()
	case MissingParametersCode:
		return ErrEmptyRequiredField.Error()
	case PermissionRequiredCode:
		return ErrPermission.Error()
	case InternalErrorCode:
		return ErrInternal.Error()
	case DBNotFoundCode:
		return ErrNotFound.Error()
	case CookieNotFoundCode:
		return ErrCookie.Error()
	case UniqueFieldCode:
		return ErrUnique.Error()
	case SMSTimeoutNeedCode:
		return ErrPhoneNumberCodeSend.Error()
	case EmailWaitConfirmCode:
		return "Ожидает подтверждения"
	}
	return ErrOops.Error()
}
