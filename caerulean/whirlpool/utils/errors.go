package utils

import (
	"fmt"
	"strings"
)

func JoinError(message string, errs ...any) error {
	traces := make([]string, len(errs))
	for i := range errs {
		traces[i] = fmt.Sprint(errs[i])
	}
	return fmt.Errorf("%s: %v", message, strings.Join(traces, ": "))
}
