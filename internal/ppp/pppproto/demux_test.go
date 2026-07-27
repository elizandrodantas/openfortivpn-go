package pppproto

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"
)

// TestDemux_ConcurrentLCPAndIPCP mirrors the real exchange observed via
// packet capture against a working FortiClient session: LCP and IPCP
// Configure-Requests go out together (not LCP fully completing before IPCP
// starts), and the peer's LCP and IPCP responses arrive interleaved, not in
// separate phases. Demux must route each to the right negotiation without
// either one losing packets meant for the other.
func TestDemux_ConcurrentLCPAndIPCP(t *testing.T) {
	link := newFakeLink()
	assigned := net.ParseIP("198.51.100.99").To4()

	done := make(chan struct{})
	go func() {
		defer close(done)

		// Read both of the client's initial requests (order between LCP and
		// IPCP is not guaranteed since they're sent from separate goroutines).
		var lcpReq, ipcpReq ConfigFrame
		for range 2 {
			pkt := link.sent(t)
			proto, payload, _ := Protocol(pkt)
			cf, _ := ParseConfigFrame(payload)
			switch proto {
			case ProtoLCP:
				lcpReq = cf
			case ProtoIPCP:
				ipcpReq = cf
			}
		}

		// Interleave responses: Nak IPCP first (peer replies out of order
		// relative to when requests were sent), then Ack LCP, then Ack the
		// resent IPCP request.
		nak := ConfigFrame{Code: CodeConfigureNak, ID: ipcpReq.ID, Options: []Option{
			{Type: IPCPOptIPAddress, Data: assigned},
		}}
		link.deliver(BuildFrame(ProtoIPCP, nak.Marshal()))

		lcpAck := ConfigFrame{Code: CodeConfigureAck, ID: lcpReq.ID, Options: lcpReq.Options}
		link.deliver(BuildFrame(ProtoLCP, lcpAck.Marshal()))

		// Expect the resent IPCP request carrying the Nak'd address.
		var ipcpReq2 ConfigFrame
		for {
			pkt := link.sent(t)
			proto, payload, _ := Protocol(pkt)
			if proto != ProtoIPCP {
				continue // could be an LCP retransmission racing in
			}
			cf, _ := ParseConfigFrame(payload)
			if cf.Code == CodeConfigureRequest {
				ipcpReq2 = cf
				break
			}
		}
		ipcpAck := ConfigFrame{Code: CodeConfigureAck, ID: ipcpReq2.ID, Options: ipcpReq2.Options}
		link.deliver(BuildFrame(ProtoIPCP, ipcpAck.Marshal()))
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	demux := NewDemux(ctx, link)

	var lcpErr, ipcpErr error
	var result IPCPResult
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		lcpErr = NegotiateLCP(ctx, demux.Link(ProtoLCP), LCPOptions{MRU: 1354})
	}()
	go func() {
		defer wg.Done()
		result, ipcpErr = NegotiateIPCP(ctx, demux.Link(ProtoIPCP), IPCPOptions{})
	}()
	wg.Wait()

	if lcpErr != nil {
		t.Fatalf("NegotiateLCP failed: %v", lcpErr)
	}
	if ipcpErr != nil {
		t.Fatalf("NegotiateIPCP failed: %v", ipcpErr)
	}
	if !result.LocalIP.Equal(net.IP(assigned)) {
		t.Errorf("LocalIP = %v, want %v", result.LocalIP, net.IP(assigned))
	}
	<-done
}

func TestDemux_PanicsOnUnsupportedProtocol(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("expected panic for unsupported protocol")
		}
	}()
	link := newFakeLink()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	demux := NewDemux(ctx, link)
	demux.Link(ProtoIPv4)
}
