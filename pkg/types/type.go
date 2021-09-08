package types

import (
	"path"
	"strings"
)

const (
	Image Media = iota + 1
	Video
	Document
	Avatar
	TreatmentAttachment
	Internal
	InternalRegistration
	InternalReports
	Temporary
)

type Media uint8

func (m Media) String() string {
	switch m {
	case Image:
		return "images"
	case Video:
		return "videos"
	case Document:
		return "documents"
	case Avatar:
		return "avatars"
	case TreatmentAttachment:
		return "treatment_attachment"
	case Internal:
		return "int"
	case InternalRegistration:
		return "reg"
	case InternalReports:
		return "reports"
	case Temporary:
		return "tmp"
	default:
		return "common"
	}
}

var (
	imagesExtensions = []string{".png", ".jpg", ".jpeg"}
)

func IsImage(file string) bool {
	ext := path.Ext(file)
	for _, x := range imagesExtensions {
		if x == strings.ToLower(ext) {
			return true
		}
	}
	return false
}

// Is checking of rules of the media type
func Is(name string, media Media) bool {
	// TODO more checks-cases
	switch media {
	case Image:
		return IsImage(name)
	default:
		return true
	}
}
