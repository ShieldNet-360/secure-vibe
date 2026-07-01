package scheduler

import "time"

// intSecondsAtLeast converts d to whole seconds, clamping below by min.
func intSecondsAtLeast(d time.Duration, min int) int {
	s := int(d / time.Second)
	if s < min {
		return min
	}
	return s
}
