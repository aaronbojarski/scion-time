//go:build linux

package clock

// Based on Ntimed by Poul-Henning Kamp, https://github.com/bsdphk/Ntimed

import (
	"unsafe"

	"math"
	"sync"
	"time"

	"go.uber.org/zap"

	"golang.org/x/sys/unix"

	"example.com/scion-time/base/timebase"
	"example.com/scion-time/base/timemath"
)

const (
	ADJ_FREQUENCY = 2

	STA_PLL      = 1
	STA_FREQHOLD = 128
)

type adjustment struct {
	clock     *SystemClock
	duration  time.Duration
	afterFreq float64
}

type SystemClock struct {
	Log        *zap.Logger
	mu         sync.Mutex
	epoch      uint64
	adjustment *adjustment
}

var _ timebase.LocalClock = (*SystemClock)(nil)

func now(log *zap.Logger) time.Time {
	var ts unix.Timespec
	err := unix.ClockGettime(unix.CLOCK_REALTIME, &ts)
	if err != nil {
		log.Fatal("unix.ClockGettime failed", zap.Error(err))
	}
	return time.Unix(ts.Unix()).UTC()
}

func sleep(log *zap.Logger, duration time.Duration) {
	fd, err := unix.TimerfdCreate(unix.CLOCK_REALTIME, unix.TFD_NONBLOCK)
	if err != nil {
		log.Fatal("unix.TimerfdCreate failed", zap.Error(err))
	}
	ts, err := unix.TimeToTimespec(now(log).Add(duration))
	if err != nil {
		log.Fatal("unix.TimeToTimespec failed", zap.Error(err))
	}
	err = unix.TimerfdSettime(fd, unix.TFD_TIMER_ABSTIME, &unix.ItimerSpec{Value: ts}, nil /* oldValue */)
	if err != nil {
		log.Fatal("unix.TimerfdSettime failed", zap.Error(err))
	}
	if fd < math.MinInt32 || math.MaxInt32 < fd {
		log.Fatal("unix.TimerfdCreate returned unexpected value")
	}
	pollFds := []unix.PollFd{
		{Fd: int32(fd), Events: unix.POLLIN},
	}
	for {
		_, err := unix.Poll(pollFds, -1 /* timeout */)
		if err == unix.EINTR {
			continue
		}
		if err != nil {
			log.Fatal("unix.Poll failed", zap.Error(err))
		}
		break
	}
	_ = unix.Close(fd)
}

func setTime(log *zap.Logger, offset time.Duration) {
	log.Debug("setting time", zap.Duration("offset", offset))
	ts, err := unix.TimeToTimespec(now(log).Add(offset))
	if err != nil {
		log.Fatal("unix.TimeToTimespec failed", zap.Error(err))
	}
	_, _, errno := unix.Syscall(unix.SYS_CLOCK_SETTIME, uintptr(unix.CLOCK_REALTIME), uintptr(unsafe.Pointer(&ts)), 0)
	if errno != 0 {
		log.Fatal("unix.SYS_CLOCK_SETTIME failed", zap.Error(err))
	}
}

func setFrequency(log *zap.Logger, frequency float64) {
	log.Debug("setting frequency", zap.Float64("frequency", frequency))
	tx := unix.Timex{
		Modes:  ADJ_FREQUENCY,
		Freq:   int64(math.Floor(frequency * 65536 * 1e6)),
		Status: STA_PLL | STA_FREQHOLD,
	}
	_, err := unix.Adjtimex(&tx)
	if err != nil {
		log.Fatal("unix.Adjtimex failed", zap.Error(err))
	}
}

func (c *SystemClock) Epoch() uint64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.epoch
}

func (c *SystemClock) Now() time.Time {
	return now(c.Log)
}

func (c *SystemClock) MaxDrift(duration time.Duration) time.Duration {
	return math.MaxInt64
}

func (c *SystemClock) Step(offset time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.adjustment != nil {
		setFrequency(c.Log, c.adjustment.afterFreq)
		c.adjustment = nil
	}
	setTime(c.Log, offset)
	if c.epoch == math.MaxUint64 {
		panic("epoch overflow")
	}
	c.epoch++
}

func (c *SystemClock) Adjust(offset, duration time.Duration, frequency float64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.adjustment != nil {
		c.adjustment = nil
	}
	if duration < 0 {
		panic("invalid duration value")
	}
	duration = duration / time.Second * time.Second
	if duration == 0 {
		duration = time.Second
	}
	setFrequency(c.Log, frequency+timemath.Seconds(offset)/timemath.Seconds(duration))
	c.adjustment = &adjustment{
		clock:     c,
		duration:  duration,
		afterFreq: frequency,
	}
	go func(log *zap.Logger, adj *adjustment) {
		sleep(log, adj.duration)
		adj.clock.mu.Lock()
		defer adj.clock.mu.Unlock()
		if adj == adj.clock.adjustment {
			setFrequency(log, adj.afterFreq)
		}
	}(c.Log, c.adjustment)
}

func (c *SystemClock) Sleep(duration time.Duration) {
	c.Log.Debug("sleeping", zap.Duration("duration", duration))
	if duration < 0 {
		panic("invalid duration value")
	}
	sleep(c.Log, duration)
}