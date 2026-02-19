package utils

import "time"

const dateFormat = "2006-01-02T15:04:05.000Z" // ISO 8601

// ISOFormat formats a date to ISO 8601 format
func ISOFormat(timestamp time.Time) string {
	return timestamp.Format(dateFormat)
}
