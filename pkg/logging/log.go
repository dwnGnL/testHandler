package logging

import (
	"fmt"
	"math"
	"os"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	log "github.com/sirupsen/logrus"
	logrus "github.com/sirupsen/logrus"
)

var timeFormat = "02/Jan/2006:15:04:05 +0500"

// Setup initialize the log instance
func Setup() {

	log.SetOutput(os.Stdout)

	//log.StandardLogger().SetOutput(F)
	// Only log the warning severity or above.
	log.SetLevel(log.DebugLevel)
}

// Logger is the logrus logger handler
func Logger(log *logrus.Logger) gin.HandlerFunc {
	hostname, err := os.Hostname()
	if err != nil {
		hostname = "unknow"
	}
	return func(c *gin.Context) {
		// other handler can change c.Path so:
		path := c.Request.URL.Path
		start := time.Now()
		c.Next()
		stop := time.Since(start)
		latency := int(math.Ceil(float64(stop.Nanoseconds()) / 1000000.0))
		statusCode := c.Writer.Status()
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
		clientUserAgent := c.Request.UserAgent()
		referer := c.Request.Referer()
		dataLength := c.Writer.Size()
		if dataLength < 0 {
			dataLength = 0
		}

		entry := logrus.NewEntry(log).WithFields(logrus.Fields{
			"hostname":   hostname,
			"statusCode": statusCode,
			"latency":    latency, // time to process
			"clientIP":   ipAddress,
			"method":     c.Request.Method,
			"path":       path,
			"referer":    referer,
			"dataLength": dataLength,
			"userAgent":  clientUserAgent,
		})

		if len(c.Errors) > 0 {
			entry.Error(c.Errors.ByType(gin.ErrorTypePrivate).String())
		} else {
			msg := fmt.Sprintf("%s - %s [%s] \"%s %s\" %d %d \"%s\" \"%s\" (%dms)", ipAddress, hostname, time.Now().Format(timeFormat), c.Request.Method, path, statusCode, dataLength, referer, clientUserAgent, latency)
			if statusCode > 499 {
				entry.Error(msg)
			} else if statusCode > 399 {
				entry.Warn(msg)
			} else {
				entry.Info(msg)
			}
		}
	}
}
