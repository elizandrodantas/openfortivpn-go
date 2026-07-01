package pppproto

import (
	"context"
	"errors"
	"fmt"
	"net"
)

// IPCPOptions configures our own outgoing IPCP Configure-Request.
type IPCPOptions struct {
	// RequestDNS mirrors pppd's "usepeerdns": propose Primary/Secondary DNS
	// options (initially 0.0.0.0) so the gateway Naks us with its real DNS
	// servers, the same way it does for IP-Address. This lets the existing
	// generic sniffing in internal/io/relay.go's extractIPCP recognize the
	// resulting Configure-Ack exactly as it would for pppd on Unix.
	RequestDNS bool
}

// IPCPResult is what we learned once IPCP reached the Opened state.
type IPCPResult struct {
	LocalIP    net.IP // our address, assigned by the gateway
	PeerIP     net.IP // gateway's own PPP address, from its Configure-Request (may be nil)
	DNS1, DNS2 net.IP
}

// NegotiateIPCP drives IPCP to the Opened state. It proposes 0.0.0.0 for our
// own IP-Address (and DNS, if requested) and adopts whatever the gateway
// Naks back — the standard dynamic-address PPP client dance, matching
// pppd's "noipdefault ipcp-accept-local" behavior. We don't support Van
// Jacobson header compression, so an IP-Compression-Protocol option in the
// peer's own Configure-Request is rejected.
func NegotiateIPCP(ctx context.Context, link Link, opts IPCPOptions) (IPCPResult, error) {
	ctx, cancel := context.WithTimeout(ctx, NegotiateTimeout)
	defer cancel()

	proposed := ipcpProposal{localIP: net.IPv4zero}
	if opts.RequestDNS {
		proposed.dns1 = net.IPv4zero
		proposed.dns2 = net.IPv4zero
	}

	id := byte(1)
	send := func() error {
		return link.Send(BuildFrame(ProtoIPCP, proposed.toConfigFrame(id).Marshal()))
	}
	if err := send(); err != nil {
		return IPCPResult{}, fmt.Errorf("pppproto: IPCP: %w", err)
	}

	var result IPCPResult
	var weAckedPeer, peerAckedUs bool
	retries := 0
	for !weAckedPeer || !peerAckedUs {
		pkt, err := link.Recv(ctx)
		if err != nil {
			return IPCPResult{}, fmt.Errorf("pppproto: IPCP negotiation: %w", err)
		}
		proto, payload, ok := Protocol(pkt)
		if !ok {
			continue
		}
		if proto == ProtoLCP {
			// A late LCP Echo-Request during IPCP negotiation; answer it so
			// the peer doesn't time out waiting on us.
			if cf, err := ParseConfigFrame(payload); err == nil && cf.Code == CodeEchoRequest {
				if ef, ok := ParseEchoFrame(payload); ok {
					reply := EchoFrame{Code: CodeEchoReply, ID: ef.ID, Magic: ef.Magic}
					_ = link.Send(BuildFrame(ProtoLCP, reply.Marshal()))
				}
			}
			continue
		}
		if proto != ProtoIPCP {
			continue
		}
		cf, err := ParseConfigFrame(payload)
		if err != nil {
			continue
		}

		switch cf.Code {
		case CodeConfigureRequest:
			resp, rejected := reviewPeerIPCPRequest(cf)
			if err := link.Send(BuildFrame(ProtoIPCP, resp.Marshal())); err != nil {
				return IPCPResult{}, fmt.Errorf("pppproto: IPCP: %w", err)
			}
			if !rejected {
				weAckedPeer = true
				if ip, ok := cf.FindOption(IPCPOptIPAddress); ok && len(ip.Data) == 4 {
					result.PeerIP = net.IP(ip.Data).To4()
				}
			}

		case CodeConfigureAck:
			if cf.ID != id {
				continue
			}
			peerAckedUs = true
			result.LocalIP = proposed.localIP
			result.DNS1 = proposed.dns1
			result.DNS2 = proposed.dns2

		case CodeConfigureNak:
			if cf.ID != id {
				continue
			}
			retries++
			if retries > maxConfigureRetries {
				return IPCPResult{}, errors.New("pppproto: IPCP negotiation did not converge")
			}
			proposed.applyNak(cf)
			id++
			if err := send(); err != nil {
				return IPCPResult{}, fmt.Errorf("pppproto: IPCP: %w", err)
			}

		case CodeConfigureReject:
			if cf.ID != id {
				continue
			}
			retries++
			if retries > maxConfigureRetries {
				return IPCPResult{}, errors.New("pppproto: IPCP negotiation did not converge")
			}
			proposed.applyReject(cf)
			id++
			if err := send(); err != nil {
				return IPCPResult{}, fmt.Errorf("pppproto: IPCP: %w", err)
			}
		}
	}
	if result.LocalIP == nil || result.LocalIP.Equal(net.IPv4zero) {
		return IPCPResult{}, errors.New("pppproto: IPCP opened without a usable local address")
	}
	return result, nil
}

// ipcpProposal tracks the option values in our own, possibly-renegotiated,
// Configure-Request.
type ipcpProposal struct {
	localIP    net.IP
	dns1, dns2 net.IP // nil = not requested
}

func (p ipcpProposal) toConfigFrame(id byte) ConfigFrame {
	cf := ConfigFrame{Code: CodeConfigureRequest, ID: id}
	cf.Options = append(cf.Options, Option{Type: IPCPOptIPAddress, Data: p.localIP.To4()})
	if p.dns1 != nil {
		cf.Options = append(cf.Options, Option{Type: IPCPOptPrimaryDNS, Data: p.dns1.To4()})
	}
	if p.dns2 != nil {
		cf.Options = append(cf.Options, Option{Type: IPCPOptSecondaryDNS, Data: p.dns2.To4()})
	}
	return cf
}

// applyNak adopts the gateway's suggested values for any option it Naked.
func (p *ipcpProposal) applyNak(cf ConfigFrame) {
	for _, o := range cf.Options {
		if len(o.Data) != 4 {
			continue
		}
		ip := net.IP(o.Data).To4()
		switch o.Type {
		case IPCPOptIPAddress:
			p.localIP = ip
		case IPCPOptPrimaryDNS:
			p.dns1 = ip
		case IPCPOptSecondaryDNS:
			p.dns2 = ip
		}
	}
}

// applyReject drops any option the gateway refuses to negotiate at all.
func (p *ipcpProposal) applyReject(cf ConfigFrame) {
	for _, o := range cf.Options {
		switch o.Type {
		case IPCPOptPrimaryDNS:
			p.dns1 = nil
		case IPCPOptSecondaryDNS:
			p.dns2 = nil
		}
	}
}

// reviewPeerIPCPRequest answers the gateway's own Configure-Request. We
// accept its IP-Address (we don't care what address it uses for its end of
// the link) and reject IP-Compression-Protocol (no Van Jacobson support)
// and anything else unrecognized.
func reviewPeerIPCPRequest(cf ConfigFrame) (resp ConfigFrame, rejected bool) {
	var reject []Option
	for _, o := range cf.Options {
		switch o.Type {
		case IPCPOptIPAddress:
			// acceptable as-is
		default:
			reject = append(reject, o)
		}
	}
	if len(reject) > 0 {
		return ConfigFrame{Code: CodeConfigureReject, ID: cf.ID, Options: reject}, true
	}
	return ConfigFrame{Code: CodeConfigureAck, ID: cf.ID, Options: cf.Options}, false
}
