package routes

import (
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

const (
	USD = "USD"
)

type funcGin func(c *gin.Context)

var DB *gorm.DB
