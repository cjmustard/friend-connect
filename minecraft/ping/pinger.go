package ping

import (
	"context"
	"net"
	"time"

	"github.com/cjmustard/console-connect/minecraft/logger"
)

type Pinger struct {
	log    *logger.Logger
	period time.Duration
	addr   string
}

func New(log *logger.Logger, addr string, period time.Duration) *Pinger {
	return &Pinger{log: log, addr: addr, period: period}
}

func (p *Pinger) Run(ctx context.Context) {
	ticker := time.NewTicker(p.period)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			p.pingOnce()
		}
	}
}

func (p *Pinger) pingOnce() {
	start := time.Now()
	conn, err := net.DialTimeout("udp", p.addr, 5*time.Second)
	if err != nil {
		p.log.Errorf("ping %s: %v", p.addr, err)
		return
	}
	_ = conn.Close()
	p.log.Debugf("ping %s succeeded in %s", p.addr, time.Since(start))
}
