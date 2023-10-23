package router

import (
	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
)

// cors middleware
func corsConfig() gin.HandlerFunc {
	config := cors.DefaultConfig()
	config.AllowAllOrigins = true
	config.AllowMethods = []string{"*"}
	config.AllowHeaders = []string{"Origin, Content-Type, Accept, Range"}
	return cors.New(config)
}
