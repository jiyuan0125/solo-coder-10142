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

	// For p <= 1 minute, m = max(p/5, 2s) = 2s; so range is roughly 3s to 7s.
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
	if minInt < 1*time.Second {
		t.Errorf("min interval %v < 1s", minInt)
	}

	// Count how many are in 3s..7s range (with m=2s jitter)
	inRange := 0
	for _, iv := range intervals {
		if iv >= 3*time.Second && iv <= 7*time.Second {
			inRange++
		}
	}
	t.Logf("in range [3s, 7s]: %d/100", inRange)
	if inRange < 90 {
		t.Errorf("too few intervals in expected range: %d/100", inRange)
	}
}

// TestSetPersistIntervalSleep verifies SetPersistInterval affects subsequent sleeps.
func TestSetPersistIntervalSleep(t *testing.T) {
	orig := 10 * time.Second
	for i, tsk := range Tasks {
		if tsk.ID() == "persistAndStat" {
			orig = tsk.Period
			defer func() { Tasks[i].Period = orig }()
			break
		}
	}

	SetPersistInterval(5 * time.Second)

	var found bool
	for _, tsk := range Tasks {
		if tsk.ID() == "persistAndStat" {
			found = true
			if tsk.Period != 5*time.Second {
				t.Errorf("persistAndStat.Period = %v, want 5s", tsk.Period)
			}
			break
		}
	}
	if !found {
		t.Error("persistAndStat task not found")
	}
	_ = rand.Int64N
}
