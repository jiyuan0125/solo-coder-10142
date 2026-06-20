// Package cron schedules jobs.
package cron

import (
	"context"
	"math/rand/v2"
	"strings"
	"time"

	"zgo.at/goatcounter/v2/pkg/bgrun"
	"zgo.at/goatcounter/v2/pkg/log"
	"zgo.at/zstd/zruntime"
	"zgo.at/zstd/zsync"
)

type Task struct {
	Desc   string
	Fun    func(context.Context) error
	Period time.Duration
}

func (t Task) ID() string {
	return strings.Replace(zruntime.FuncName(t.Fun), "zgo.at/goatcounter/v2/cron.", "", 1)
}

var Tasks = []Task{
	{"vacuum pageviews (data retention)", dataRetention, 24 * time.Hour},
	{"vacuum pageviews (old bot)", oldBot, 24 * time.Hour},
	{"vacuum soft-deleted sites", vacuumDeleted, 12 * time.Hour},
	{"renew ACME certs", renewACME, 2 * time.Hour},
	{"rm old exports", oldExports, 1 * time.Hour},
	{"send email reports", EmailReports, 1 * time.Hour},
	{"cycle sessions", sessions, 1 * time.Minute},
	{"persist hits", persistAndStat, 10 * time.Second},
	{"vacuum filters", oldFilters, 1 * time.Hour},
}

var (
	stopped = zsync.NewAtomicInt(0)
	started = zsync.NewAtomicInt(0)
)

func SetPersistInterval(d time.Duration) {
	for i, t := range Tasks {
		if t.ID() == "persistAndStat" {
			Tasks[i].Period = d
			break
		}
	}
}

func addJitter(p time.Duration) time.Duration {
	var m time.Duration
	switch {
	case p >= time.Hour*12:
		m = p / 100
	case p <= time.Minute:
		m = p / 5
		if m < 2*time.Second {
			m = 2 * time.Second
		}
	default:
		m = p / 50
	}
	if m > 0 {
		rnd := time.Duration(rand.Int64N(int64(m))).Round(time.Second)
		if rand.IntN(2) == 1 {
			rnd = -rnd
		}
		p += rnd
	}
	return p
}

func initialDelay(p time.Duration) time.Duration {
	if p <= 0 {
		return 0
	}
	max := p / 4
	if max < 1*time.Second {
		max = 1 * time.Second
	}
	if max > 30*time.Second {
		max = 30 * time.Second
	}
	return time.Duration(rand.Int64N(int64(max)))
}

// Start running tasks in the background.
func Start(ctx context.Context) {
	if started.Value() == 1 {
		return
	}
	started.Set(1)

	l := log.Module("cron")

	for _, t := range Tasks {
		f := t.ID()
		bgrun.NewTask("cron:"+f, 1, func(context.Context) error {
			err := t.Fun(ctx)
			if err != nil {
				l.Error(ctx, err, "task", f)
			}
			return nil
		})
	}

	for _, t := range Tasks {
		go func(t Task) {
			defer log.Recover(ctx)

			id := t.ID()
			time.Sleep(initialDelay(t.Period))

			for {
				if stopped.Value() == 1 {
					return
				}

				p := addJitter(t.Period)
				time.Sleep(p)

				if stopped.Value() == 1 {
					return
				}

				err := bgrun.RunTask("cron:" + id)
				if err != nil {
					log.Error(ctx, err)
				}
			}
		}(t)
	}
}

func Stop() error {
	stopped.Set(1)
	started.Set(0)
	bgrun.Wait("")
	bgrun.Reset()
	return nil
}

func TaskOldExports() error     { return bgrun.RunTask("cron:oldExports") }
func TaskDataRetention() error  { return bgrun.RunTask("cron:dataRetention") }
func TaskVacuumOldSites() error { return bgrun.RunTask("cron:vacuumDeleted") }
func TaskACME() error           { return bgrun.RunTask("cron:renewACME") }
func TaskSessions() error       { return bgrun.RunTask("cron:sessions") }
func TaskEmailReports() error   { return bgrun.RunTask("cron:emailReports") }
func TaskPersistAndStat() error { return bgrun.RunTask("cron:persistAndStat") }
func WaitOldExports()           { bgrun.Wait("cron:oldExports") }
func WaitDataRetention()        { bgrun.Wait("cron:dataRetention") }
func WaitVacuumOldSites()       { bgrun.Wait("cron:vacuumDeleted") }
func WaitACME()                 { bgrun.Wait("cron:renewACME") }
func WaitSessions()             { bgrun.Wait("cron:sessions") }
func WaitEmailReports()         { bgrun.Wait("cron:emailReports") }
func WaitPersistAndStat()       { bgrun.Wait("cron:persistAndStat") }
