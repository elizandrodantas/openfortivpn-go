package pppproto

import (
	"context"
	"fmt"
)

// Demux fans out packets from an underlying Link to one Link view per
// protocol: LCP, IPCP, and everything else (IPv4 data, or protocols we
// don't support). It is meant to be the only reader of the underlying Link
// for the whole session, so the LCP/IPCP negotiation, the ServeLCP/
// ServeIPCP responders and the data path never race each other for
// packets: the gateway's IPCP Configure-Request, which arrives while LCP is
// still finishing, simply waits in the IPCP queue until NegotiateIPCP reads
// it, and no data packet is ever dropped by a control-plane reader.
type Demux struct {
	link  Link
	lcp   chan []byte
	ipcp  chan []byte
	other chan []byte
	// err is why run stopped. It's written before the queues are closed,
	// so any reader that sees a closed queue also sees it.
	err error
}

// NewDemux starts fanning out packets from link in the background. It stops
// when ctx is done or link.Recv returns an error.
func NewDemux(ctx context.Context, link Link) *Demux {
	d := &Demux{
		link:  link,
		lcp:   make(chan []byte, 64),
		ipcp:  make(chan []byte, 64),
		other: make(chan []byte, 256),
	}
	go d.run(ctx)
	return d
}

func (d *Demux) run(ctx context.Context) {
	defer close(d.lcp)
	defer close(d.ipcp)
	defer close(d.other)
	for {
		pkt, err := d.link.Recv(ctx)
		if err != nil {
			d.err = err
			return
		}
		proto, _, ok := Protocol(pkt)
		if !ok {
			continue
		}
		var ch chan []byte
		switch proto {
		case ProtoLCP:
			ch = d.lcp
		case ProtoIPCP:
			ch = d.ipcp
		default:
			ch = d.other
		}
		select {
		case ch <- pkt:
		case <-ctx.Done():
			d.err = ctx.Err()
			return
		}
	}
}

// Other returns a Link view that receives every packet that is neither LCP
// nor IPCP.
func (d *Demux) Other() Link {
	return &demuxLink{demux: d, ch: d.other}
}

// Link returns a Link view that sends via the underlying transport (shared
// across all views — the caller's Link.Send must be safe for concurrent
// use) and receives only packets of the given protocol.
func (d *Demux) Link(proto uint16) Link {
	var ch <-chan []byte
	switch proto {
	case ProtoLCP:
		ch = d.lcp
	case ProtoIPCP:
		ch = d.ipcp
	default:
		panic(fmt.Sprintf("pppproto: Demux.Link: unsupported protocol %#04x", proto))
	}
	return &demuxLink{demux: d, ch: ch}
}

type demuxLink struct {
	demux *Demux
	ch    <-chan []byte
}

func (l *demuxLink) Send(pkt []byte) error { return l.demux.link.Send(pkt) }

func (l *demuxLink) Recv(ctx context.Context) ([]byte, error) {
	select {
	case pkt, ok := <-l.ch:
		if !ok {
			if l.demux.err != nil {
				return nil, l.demux.err
			}
			return nil, fmt.Errorf("pppproto: demux: link closed")
		}
		return pkt, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}
