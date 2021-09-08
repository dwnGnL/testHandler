package e

type Field struct {
	Name    string `json:"field,omitempty"`
	Message string `json:"message,omitempty"`
	Tag     string `json:"tag,omitempty"`
}

func (e Field) Error() string {
	return e.Message
}

// Deprecated
func NewPermissionError() *Field {
	return &Field{Message: ErrPermission.Error()}
}
