package types

import (
	"fmt"

	"github.com/gin-gonic/gin"
)

type HttpHeader string

const (
	// Common headers
	baseHeader          HttpHeader = "X-Hub-"
	HttpHeaderErr                  = baseHeader + "Err"
	HttpHeaderErrDetail            = HttpHeaderErr + "-Detail"
	HttpHeaderTimeout              = baseHeader + "Timeout"
	HttpHeaderTotal                = baseHeader + "Total"
	HttpHeaderPage                 = baseHeader + "Page"
	HttpHeaderFilters              = baseHeader + "Filters"

	// Identifiers

	HttpUserId       = baseHeader + "User-Id"
	HttpUserRoles    = baseHeader + "User-Roles"
	HttpUserIsActive = baseHeader + "User-Is-Active"

	// Headers of positions.Position
	HttpPositionHeader              = baseHeader + "Position-Id"
	HttpPositionKindHeader          = baseHeader + "Position-Kind"
	HttpPositionRegionsHeader       = baseHeader + "Position-Regions"
	HttpPositionDistrictsHeader     = baseHeader + "Position-Districts"
	HttpPositionTermsOfOfficeHeader = baseHeader + "Position-Terms-Of-Office"
	HttpPositionDisplayHeader       = baseHeader + "Position-Display"
	HttpPositionUserIdHeader        = baseHeader + "Position-User-Id"
	HttpPositionUserNameHeader      = baseHeader + "Position-User-Name"
	HttpPositionUserRegionHeader    = baseHeader + "Position-User-Region"
)

func (h HttpHeader) String() string {
	return string(h)
}

func (h HttpHeader) Set(val string, c *gin.Context) {
	c.Header(string(h), val)
}

func (h HttpHeader) SetInt(val int, c *gin.Context) {
	c.Header(string(h), fmt.Sprint(val))
}

func (h HttpHeader) Get(c *gin.Context) string {
	return c.GetHeader(string(h))
}
