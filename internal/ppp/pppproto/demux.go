package pppproto

import (
	"context"
	"fmt"
)

// Demux fans out packets from an underlying Link to one Link view per
// protocol, so NegotiateLCP and NegotiateIPCP can run concurrently over a
// single transport without racing to consume each other's packets from one
// shared Recv call.
//
// This matters because a real gateway is not necessarily obligated to
// finish LCP before it will accept IPCP: packet-capture comparison against
// a working client showed LCP and IPCP Configure-Requests going out
// together, not LCP fully completing before IPCP starts. A strictly
// sequential client can end up waiting on a peer that isn't paying
// attention to a lone, late IPCP request.
type Demux struct {
	link Link
	lcp  chan []byte
	ipcp chan []byte
	errc chan error
}

// NewDemux starts fanning out packets from link in the background. It stops
// when ctx is done or link.Recv returns an error.
func NewDemux(ctx context.Context, link Link) *Demux {
	d := &Demux{
		link: link,
		lcp:  make(chan []byte, 64),
		ipcp: make(chan []byte, 64),
		errc: make(chan error, 1),
	}
	go d.run(ctx)
	return d
}

func (d *Demux) run(ctx context.Context) {
	defer close(d.lcp)
	defer close(d.ipcp)
	for {
		pkt, err := d.link.Recv(ctx)
		if err != nil {
			select {
			case d.errc <- err:
			default:
			}
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
			continue // e.g. CCP, or IPv4 data arriving before we're ready for it
		}
		select {
		case ch <- pkt:
		case <-ctx.Done():
			return
		}
	}
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
			select {
			case err := <-l.demux.errc:
				return nil, err
			default:
				return nil, fmt.Errorf("pppproto: demux: link closed")
			}
		}
		return pkt, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}
