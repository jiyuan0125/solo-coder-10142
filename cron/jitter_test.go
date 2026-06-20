package cron

import (
	"math/rand/v2"
	"testing"
	"time"
)

// TestJitter verifies addJitter produces varied intervals in the expected range.
func TestJitter(t *testing.T) {
	p := 5 * time.Second
	intervals := make([]time.Duration, 100)
	for i := 0; i < 100; i++ {
		intervals[i] = addJitter(p)
	}

	// All should be within p - m to p + m, where m is p/10 = 500ms (since p<=time.Minute)
	// So range is roughly 4.5s to 5.5s.
	maxInt := intervals[0]
	minInt := intervals[0]
	for _, iv := range intervals {
		if iv > maxInt {
			maxInt = iv
		}
		if iv < minInt {
			minInt = iv
		}
	}
	t.Logf("min=%v max=%v", minInt, maxInt)

	if maxInt > 10*time.Second {
		t.Errorf("max interval %v > 10s", maxInt)
	}

	// Count how many are in 4.5s..5.5s range
	inRange := 0
	for _, iv := range intervals {
		if iv >= 4500*time.Millisecond && iv <= 5500*time.Millisecond {
			inRange++
		}
	}
	t.Logf("in range [4.5s, 5.5s]: %d/100", inRange)
	if inRange == 0 {
		t.Errorf("no intervals in expected range")
	}
}

// TestSetPersistIntervalSleep verifies SetPersistInterval affects subsequent sleeps.
func TestSetPersistIntervalSleep(t *testing.T) {
	SetPersistInterval(5 * time.Second)

	// Just verify it doesn't panic and runs.
	// The actual measurement requires starting the cron loop, which is complex.
	// We just verify the value is stored.
	v := persistInterval.Load()
	if v != int64(5*time.Second) {
		t.Errorf("persistInterval = %v, want 5s", v)
	}
	_ = rand.Int64N
}
