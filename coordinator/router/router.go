package router

import (
	"github.com/gin-gonic/gin"
)

func SetupRouter(maxMultiPartMem int64) *gin.Engine {
	// create gin router
	gin.SetMode(gin.DebugMode) // use release mode before deployment
	router := gin.Default()
	router.MaxMultipartMemory = maxMultiPartMem

	// add gin middleware
	router.Use(corsConfig())

	return router
}
