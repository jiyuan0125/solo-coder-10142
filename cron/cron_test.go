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

func applyJitter(p time.Duration) time.Duration {
	if p > 0 {
		m := p / 50
		if p >= time.Hour*12 {
			m = p / 100
		}
		if m < time.Millisecond {
			m = time.Millisecond
		}
		rnd := time.Duration(rand.Int64N(int64(m))).Round(time.Millisecond)
		if rand.IntN(2) == 1 {
			rnd = -rnd
		}
		p += rnd
	}
	return p
}

func TestJitterPersistAndStat10s(t *testing.T) {
	base := 10 * time.Second
	intervals := make(map[time.Duration]int)

	for range 100 {
		p := applyJitter(base)
		intervals[p]++
	}

	if len(intervals) < 2 {
		t.Errorf("10s persist interval should have at least 2 distinct values from 100 samples, got %d", len(intervals))
	}

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

	t.Logf("10s persist: %d distinct intervals from 100 samples", len(intervals))
	for p, c := range intervals {
		t.Logf("  %s: %d times", p, c)
	}
}

func TestJitterOneMinute(t *testing.T) {
	base := 1 * time.Minute
	intervals := make(map[time.Duration]int)

	for range 200 {
		p := applyJitter(base)
		intervals[p]++
	}

	if len(intervals) < 5 {
		t.Errorf("1m interval should have at least 5 distinct values from 200 samples, got %d", len(intervals))
	}

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

func TestJitterLongPeriod(t *testing.T) {
	base := 1 * time.Hour
	intervals := make(map[time.Duration]int)

	for range 200 {
		p := applyJitter(base)
		intervals[p]++
	}

	if len(intervals) < 10 {
		t.Errorf("1h interval should have at least 10 distinct values from 200 samples, got %d", len(intervals))
	}

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
