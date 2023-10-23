package constants

const (
	MaxTimeDifference     = 600        // time difference between recryptor and authorizer must be less than 10 minutes
	MaxDecryptionDuration = 3 * 3600   // three hours
	ChunkSize             = 256 * 1024 // 256KB
	MaxSkippedChunk       = 20
	MaxMemForParsing      = 2 * 1024 * 1024 // maximum DRAM ParseMultipartForm can use
)
