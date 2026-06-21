package cron_test

import (
	"math/rand/v2"
	"testing"
	"time"

	"zgo.at/goatcounter/v2/cron"
)

func TestTaskGetPeriod(t *testing.T) {
	t.Run("static period", func(t *testing.T) {
		task := cron.Task{Period: 2 * time.Hour}
		if task.GetPeriod() != 2*time.Hour {
			t.Errorf("want 2h, got %s", task.GetPeriod())
		}
	})

	t.Run("dynamic PeriodFunc overrides static Period", func(t *testing.T) {
		called := 0
		task := cron.Task{
			Period:     1 * time.Hour,
			PeriodFunc: func() time.Duration { called++; return 5 * time.Minute },
		}
		got := task.GetPeriod()
		if got != 5*time.Minute {
			t.Errorf("want 5m, got %s", got)
		}
		if called != 1 {
			t.Errorf("PeriodFunc not called")
		}
	})
}

func TestSetPersistIntervalUpdatesPeriod(t *testing.T) {
	var persistTask *cron.Task
	for i := range cron.Tasks {
		if cron.Tasks[i].ID() == "persistAndStat" {
			persistTask = &cron.Tasks[i]
			break
		}
	}
	if persistTask == nil {
		t.Fatal("persistAndStat task not found")
	}
	if persistTask.PeriodFunc == nil {
		t.Fatal("persistAndStat should have PeriodFunc set")
	}

	before := persistTask.GetPeriod()
	cron.SetPersistInterval(42 * time.Second)
	after := persistTask.GetPeriod()
	cron.SetPersistInterval(10 * time.Second)

	if after != 42*time.Second {
		t.Errorf("SetPersistInterval not reflected; want 42s got %s (before: %s)", after, before)
	}
}

func TestJitterProducesDiverseIntervals(t *testing.T) {
	base := 1 * time.Hour
	intervals := make(map[time.Duration]int)

	// Simulate the jitter logic in cron.Start()
	for range 200 {
		p := base
		if p > time.Minute {
			m := p / 50
			rnd := time.Duration(rand.Int64N(int64(m))).Round(time.Second)
			if rand.IntN(2) == 1 {
				rnd = -rnd
			}
			p += rnd
		}
		intervals[p]++
	}

	// With jitter, we should see multiple distinct interval values
	if len(intervals) < 10 {
		t.Errorf("jitter not diverse enough: got %d distinct intervals from 200 samples, want >= 10", len(intervals))
	}

	// All intervals should stay within ±2% of the base (m = base/50 = 2%)
	maxJitter := base / 50
	for p := range intervals {
		diff := p - base
		if diff < 0 {
			diff = -diff
		}
		if diff > maxJitter {
			t.Errorf("interval %s deviates too far from base %s (max diff %s)", p, base, maxJitter)
		}
	}
}
