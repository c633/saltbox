package util

import (
	"log"

	"github.com/awnumar/memguard"
)

func Fatal(err error) {
	log.Println(err)
	memguard.SafeExit(1)
}
