package client

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync/atomic"
	"time"

	"github.com/scionproto/scion/pkg/snet"
	"gitlab.com/hacklunch/ntske"

	"go.uber.org/zap"

	"example.com/scion-time/base/crypto"
	"example.com/scion-time/base/timemath"
	"example.com/scion-time/net/scion"
	"example.com/scion-time/net/udp"
)

type measurement struct {
	off time.Duration
	err error
}

type ReferenceClock interface {
	MeasureClockOffset(ctx context.Context, log *zap.Logger) (time.Duration, error)
}

type ReferenceClockClient struct {
	numOpsInProgress uint32
}

var (
	errNoPaths = errors.New("failed to measure clock offset: no paths")
)

func printmeta(meta ntske.Data, log *zap.Logger) {
	fmt.Printf("NTSKE exchange yielded:\n"+
		"  c2s: %x\n"+
		"  s2c: %x\n"+
		"  server: %v\n"+
		"  port: %v\n"+
		"  algo: %v\n",
		string(meta.C2sKey),
		string(meta.S2cKey),
		meta.Server,
		meta.Port,
		meta.Algo,
	)

	fmt.Printf("  %v cookies:\n", len(meta.Cookie))
	for i, cookie := range meta.Cookie {
		fmt.Printf("  #%v: %x\n", i+1, cookie)
	}
}

func MeasureClockOffsetNtsIP(ctx context.Context, log *zap.Logger,
	ntpc *IPNtsClient, localAddr, remoteAddr *net.UDPAddr) (
	time.Duration, error) {
	var err error
	var off time.Duration

	// First do key exchange and save Keys and cookies in ntpc struct
	// - TCP TLS handshake
	// - KE
	// - Must store port and server somewhere
	//    - could use the ntske Data struct and store in IPNtsClient
	if ntpc.KeyExchange == nil {
		tlsconfig, err := tlsSetup(false)
		if err != nil {
			log.Fatal("Couldn't set up TLS: ", zap.Error(err))
		}

		server := "nts.netnod.se" //For TLS certificate we need the string IP address. Otherwise use remoteAddr.IP.String()

		ke, err := keyExchange(server, tlsconfig, true)
		if err != nil {
			log.Error("NTS-KE exchange error: ", zap.Error(err))
		}
		printmeta(ke.Meta, log)
		ntpc.KeyExchange = ke
	}
	// Do query using cookies and possibly request new ones

	o, _, e := ntpc.measureClockOffsetIP(ctx, log, localAddr, remoteAddr)
	if e == nil {
		off, err = o, e
	} else {
		log.Info("failed to measure clock offset", zap.Stringer("to", remoteAddr), zap.Error(e))
	}

	return off, err
}

func MeasureClockOffsetIP(ctx context.Context, log *zap.Logger,
	ntpc *IPClient, localAddr, remoteAddr *net.UDPAddr) (
	time.Duration, error) {
	var err error
	var off time.Duration
	var nerr, n int
	if ntpc.InterleavedMode {
		n = 2
	} else {
		n = 1
	}
	for i := 0; i != n; i++ {
		o, _, e := ntpc.measureClockOffsetIP(ctx, log, localAddr, remoteAddr)
		if e == nil {
			off, err = o, e
		} else {
			if nerr == i {
				off, err = o, e
			}
			nerr++
			log.Info("failed to measure clock offset",
				zap.Stringer("to", remoteAddr), zap.Error(e))
		}
	}
	return off, err
}

func collectMeasurements(ctx context.Context, off []time.Duration, ms chan measurement) int {
	i := 0
	j := 0
	n := len(off)
loop:
	for i != n {
		select {
		case m := <-ms:
			if m.err == nil {
				if j != len(off) {
					off[j] = m.off
					j++
				}
			}
			i++
		case <-ctx.Done():
			break loop
		}
	}
	go func(n int) { // drain channel
		for n != 0 {
			<-ms
			n--
		}
	}(n - i)
	return j
}

func MeasureClockOffsetSCION(ctx context.Context, log *zap.Logger,
	ntpcs []*SCIONClient, localAddr, remoteAddr udp.UDPAddr, ps []snet.Path) (
	time.Duration, error) {
	sps := make([]snet.Path, len(ntpcs))
	n, err := crypto.Sample(ctx, len(sps), len(ps), func(dst, src int) {
		sps[dst] = ps[src]
	})
	if err != nil {
		return 0, err
	}
	if n == 0 {
		return 0, errNoPaths
	}
	sps = sps[:n]

	off := make([]time.Duration, len(sps))
	ms := make(chan measurement)
	for i := 0; i != len(sps); i++ {
		go func(ctx context.Context, ntpc *SCIONClient,
			localAddr, remoteAddr udp.UDPAddr, p snet.Path) {
			var err error
			var off time.Duration
			var nerr, n int
			log.Debug("measuring clock offset",
				zap.Stringer("to", remoteAddr.IA),
				zap.Object("via", scion.PathMarshaler{Path: p}),
			)
			if ntpc.InterleavedMode {
				ntpc.ResetInterleavedMode()
				n = 2
			} else {
				n = 1
			}
			for j := 0; j != n; j++ {
				o, _, e := ntpc.measureClockOffsetSCION(ctx, log, localAddr, remoteAddr, p)
				if e == nil {
					off, err = o, e
				} else {
					if nerr == j {
						off, err = o, e
					}
					nerr++
					log.Info("failed to measure clock offset",
						zap.Stringer("to", remoteAddr.IA),
						zap.Object("via", scion.PathMarshaler{Path: p}),
						zap.Error(e),
					)
				}
			}
			ms <- measurement{off, err}
		}(ctx, ntpcs[i], localAddr, remoteAddr, sps[i])
	}
	collectMeasurements(ctx, off, ms)
	return timemath.Median(off), nil
}

func (c *ReferenceClockClient) MeasureClockOffsets(ctx context.Context, log *zap.Logger,
	refclks []ReferenceClock, off []time.Duration) {
	if len(off) != len(refclks) {
		panic("number of result offsets must be equal to the number of reference clocks")
	}
	swapped := atomic.CompareAndSwapUint32(&c.numOpsInProgress, 0, 1)
	if !swapped {
		panic("too many reference clock offset measurements in progress")
	}
	defer func(addr *uint32) {
		swapped := atomic.CompareAndSwapUint32(addr, 1, 0)
		if !swapped {
			panic("inconsistent count of reference clock offset measurements")
		}
	}(&c.numOpsInProgress)

	ms := make(chan measurement)
	for _, refclk := range refclks {
		go func(ctx context.Context, log *zap.Logger, refclk ReferenceClock) {
			off, err := refclk.MeasureClockOffset(ctx, log)
			ms <- measurement{off, err}
		}(ctx, log, refclk)
	}
	collectMeasurements(ctx, off, ms)
}
