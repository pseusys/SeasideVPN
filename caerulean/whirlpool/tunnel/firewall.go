package tunnel

import (
	"encoding/binary"
	"fmt"
	"main/users"
	"main/utils"
	"net"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/sirupsen/logrus"
)

const (
	SEASIDE_TABLE_NAME        = "seaside"
	NFTABLES_INFO_LEVEL       = 6
	NFTABLES_LOG_THRESHOLD    = 5
	NFTABLES_DEFAULT_REGISTER = 1

	ANY_PROTOCOL_NUMBER     = -1
	TCP_PROTOCOL_NUMBER     = 6
	UDP_PROTOCOL_NUMBER     = 17
	ICMP_V4_PROTOCOL_NUMBER = 1
	ICMP_V6_PROTOCOL_NUMBER = 58
	DESTINATION_PORT_OFFSET = 2
	IPV4_DESTINATION_OFFSET = 16
	IPV6_DESTINATION_OFFSET = 24

	DEFAULT_HASHLIMIT_VALUE = -1
	DEFAULT_HIGH_PRIORITY   = -100
)

// Create "limit" iptable rule appendix (as a string array).
// Accept environment variable name and template string where the value will be inserted (packet/second or kbyte/second, etc.).
// Also accept maximum number of user supported by VPN and burst multiplier (integers).
// Burst multiplier is applied when large amount of data comes at the same time, doesn't last for long.
// At that time, packet limit is getting multiplied by this multiplier.
// Return rule appendix string array.
func calculateLimitAndBurst(envVar string, userNumber int32, burstMultiplier uint32) (int32, uint32) {
	limitNumber := int32(utils.GetIntEnv(envVar, DEFAULT_HASHLIMIT_VALUE, 32)) * userNumber
	return limitNumber, uint32(limitNumber) * burstMultiplier
}

func createInputRule(chain *nftables.Chain, iface string, address net.IP, port *uint16, rate int32, burst uint32, prefix string, protocolType int8, isIpV6 bool) *nftables.Rule {
	var daddrLen uint32
	var daddrOffset uint32
	if isIpV6 {
		daddrLen = net.IPv6len
		daddrOffset = IPV6_DESTINATION_OFFSET
		address = address.To16()
	} else {
		daddrLen = net.IPv4len
		daddrOffset = IPV4_DESTINATION_OFFSET
		address = address.To4()
	}

	var limitType expr.LimitType
	if protocolType == ANY_PROTOCOL_NUMBER {
		limitType = expr.LimitTypePktBytes
	} else {
		limitType = expr.LimitTypePkts
	}

	expressions := []expr.Any{}

	// Match "iifname == internalIface"
	expressions = append(expressions, []expr.Any{
		&expr.Meta{
			Key:      expr.MetaKeyIIFNAME,
			Register: NFTABLES_DEFAULT_REGISTER,
		},
		&expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: NFTABLES_DEFAULT_REGISTER,
			Data:     NullTerminatedString(iface),
		},
	}...)

	// TODO: replace with src/dst address expressions once available!
	// Match "daddr == internalAddr" (position is different for IPv4 and IPv6)
	expressions = append(expressions, []expr.Any{
		&expr.Payload{
			DestRegister: NFTABLES_DEFAULT_REGISTER,
			Base:         expr.PayloadBaseNetworkHeader,
			Offset:       daddrOffset,
			Len:          daddrLen,
		},
		&expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: NFTABLES_DEFAULT_REGISTER,
			Data:     address,
		},
	}...)

	// Match protocol number (if required)
	if protocolType != ANY_PROTOCOL_NUMBER {
		expressions = append(expressions, []expr.Any{
			&expr.Meta{
				Key:      expr.MetaKeyL4PROTO,
				Register: NFTABLES_DEFAULT_REGISTER,
			},
			&expr.Cmp{
				Register: NFTABLES_DEFAULT_REGISTER,
				Op:       expr.CmpOpEq,
				Data:     []byte{byte(protocolType)},
			},
		}...)
	}

	// Match "dport == port" (position is the same for TCP and UDP)
	if protocolType == TCP_PROTOCOL_NUMBER || protocolType == UDP_PROTOCOL_NUMBER {
		portBytes := binary.BigEndian.AppendUint16(nil, *port)
		expressions = append(expressions, []expr.Any{
			&expr.Payload{
				DestRegister: NFTABLES_DEFAULT_REGISTER,
				Base:         expr.PayloadBaseTransportHeader,
				Offset:       DESTINATION_PORT_OFFSET,
				Len:          uint32(len(portBytes)),
			},
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: NFTABLES_DEFAULT_REGISTER,
				Data:     portBytes,
			},
		}...)
	}

	// Add limit, log action and final verdict
	expressions = append(expressions, []expr.Any{
		&expr.Limit{
			Type:  limitType,
			Rate:  uint64(rate),
			Over:  true,
			Unit:  expr.LimitTimeSecond,
			Burst: burst,
		},

		&expr.Log{
			Level:      NFTABLES_INFO_LEVEL,
			QThreshold: NFTABLES_LOG_THRESHOLD,
			Data:       NullTerminatedString(prefix),
		},

		&expr.Verdict{
			Kind: expr.VerdictDrop,
		},
	}...)

	// Return the rule
	return &nftables.Rule{
		Table: chain.Table,
		Chain: chain,
		Exprs: expressions,
	}
}

func createForwardRule(chain *nftables.Chain, internalIface string, externalIface string) *nftables.Rule {
	return &nftables.Rule{
		Table: chain.Table,
		Chain: chain,
		Exprs: []expr.Any{
			&expr.Meta{
				Key:      expr.MetaKeyIIFNAME,
				Register: NFTABLES_DEFAULT_REGISTER,
			},

			&expr.Cmp{
				Register: NFTABLES_DEFAULT_REGISTER,
				Op:       expr.CmpOpEq,
				Data:     NullTerminatedString(internalIface),
			},

			&expr.Meta{
				Key:      expr.MetaKeyOIFNAME,
				Register: NFTABLES_DEFAULT_REGISTER,
			},

			&expr.Cmp{
				Register: NFTABLES_DEFAULT_REGISTER,
				Op:       expr.CmpOpEq,
				Data:     NullTerminatedString(externalIface),
			},

			&expr.Verdict{
				Kind: expr.VerdictAccept,
			},
		},
	}
}

func createLogAndBlockRule(chain *nftables.Chain, prefix string) *nftables.Rule {
	return &nftables.Rule{
		Table: chain.Table,
		Chain: chain,
		Exprs: []expr.Any{
			&expr.Log{
				Level:      NFTABLES_INFO_LEVEL,
				QThreshold: NFTABLES_LOG_THRESHOLD,
				Data:       NullTerminatedString(prefix),
			},

			&expr.Verdict{
				Kind: expr.VerdictDrop,
			},
		},
	}
}

func createMasqueradeRule(chain *nftables.Chain, iface string) *nftables.Rule {
	return &nftables.Rule{
		Table: chain.Table,
		Chain: chain,
		Exprs: []expr.Any{
			&expr.Meta{
				Key:      expr.MetaKeyOIFNAME,
				Register: NFTABLES_DEFAULT_REGISTER,
			},

			&expr.Cmp{
				Register: NFTABLES_DEFAULT_REGISTER,
				Op:       expr.CmpOpEq,
				Data:     NullTerminatedString(iface),
			},

			&expr.Masq{
				Random: true,
			},

			&expr.Verdict{
				Kind: expr.VerdictAccept,
			},
		},
	}
}

// Setup iptables configuration for VPN usage.
// First, flush all iptables rules, setup allowed incoming packet patterns and drop all the other packets.
// Then, setup forwarding from external to tunnel interface and back, also enabling masquerade for external interface outputs.
// Should be applied for TunnelConf object.
// Accept internal and external IP addresses as strings, seaside, network and control ports as integers.
// Return error if configuration was not successful, nil otherwise.
func (conf *TunnelConfig) openForwarding(intIP, extIP string, apiPort, portPort, typhoonPort uint16) error {
	// Look for iptables configurations
	maxViridians := utils.GetIntEnv("SEASIDE_MAX_VIRIDIANS", users.DEFAULT_MAX_VIRIDIANS, 32)
	maxAdmins := utils.GetIntEnv("SEASIDE_MAX_ADMINS", users.DEFAULT_MAX_ADMINS, 32)
	maxTotal := int32(maxViridians + maxAdmins)
	burstMultiplier := uint32(utils.GetIntEnv("SEASIDE_BURST_LIMIT_MULTIPLIER", DEFAULT_BURST_MULTIPLIER, 32))

	// Build iptables limits
	vpnDataLimit, vpnDataBurst := calculateLimitAndBurst("SEASIDE_VPN_DATA_LIMIT", maxTotal, burstMultiplier)
	controlPacketLimit, controlPacketBurst := calculateLimitAndBurst("SEASIDE_CONTROL_PACKET_LIMIT", maxTotal, burstMultiplier)
	icmpPacketLimit, icmpPacketBurst := calculateLimitAndBurst("SEASIDE_ICMP_PACKET_LIMIT", maxTotal, burstMultiplier)

	// Prepare interface names and port numbers as strings
	tunIface := conf.Tunnel.Name()

	intIface, err := findInterfaceByIP(intIP)
	if err != nil {
		return fmt.Errorf("error finding interface for internal IP %s: %v", intIP, err)
	}

	intAddr := net.ParseIP(intIP)
	if intAddr == nil {
		return fmt.Errorf("error parsing internal IP %s: %v", intIP, err)
	}

	extIface, err := findInterfaceByIP(extIP)
	if err != nil {
		return fmt.Errorf("error finding interface for external IP %s: %v", extIP, err)
	}

	extAddr := net.ParseIP(extIP)
	if extAddr == nil {
		return fmt.Errorf("error parsing external IP %s: %v", extIP, err)
	}

	// Create nftables connection and default policy
	conn, err := nftables.New()
	if err != nil {
		return fmt.Errorf("error opening nftables connection: %v", err)
	}
	defaultPolicy := nftables.ChainPolicyAccept

	// Create nftables table
	conf.Nftable = conn.AddTable(&nftables.Table{
		Family: nftables.TableFamilyINet,
		Name:   SEASIDE_TABLE_NAME,
	})

	// Create nftables table input chain
	chain := conn.AddChain(&nftables.Chain{
		Name:     "input",
		Table:    conf.Nftable,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookInput,
		Priority: nftables.ChainPriorityFilter,
		Policy:   &defaultPolicy,
	})

	// Add input nftables rules
	if controlPacketLimit > 0 {
		conn.AddRule(createInputRule(chain, intIface.Name, intAddr, &typhoonPort, controlPacketLimit, controlPacketBurst, "Nftables drop: TYPHOON IPv4 hashlimit: ", UDP_PROTOCOL_NUMBER, false))
		conn.AddRule(createInputRule(chain, intIface.Name, intAddr, &typhoonPort, controlPacketLimit, controlPacketBurst, "Nftables drop: TYPHOON IPv6 hashlimit: ", UDP_PROTOCOL_NUMBER, true))
	}

	if controlPacketLimit > 0 {
		conn.AddRule(createInputRule(chain, intIface.Name, intAddr, &portPort, controlPacketLimit, controlPacketBurst, "Nftables drop: PORT IPv4 hashlimit: ", TCP_PROTOCOL_NUMBER, false))
		conn.AddRule(createInputRule(chain, intIface.Name, intAddr, &portPort, controlPacketLimit, controlPacketBurst, "Nftables drop: PORT IPv6 hashlimit: ", TCP_PROTOCOL_NUMBER, true))
	}

	if controlPacketLimit > 0 {
		conn.AddRule(createInputRule(chain, intIface.Name, intAddr, &apiPort, controlPacketLimit, controlPacketBurst, "Nftables drop: API IPv4 hashlimit: ", TCP_PROTOCOL_NUMBER, false))
		conn.AddRule(createInputRule(chain, intIface.Name, intAddr, &apiPort, controlPacketLimit, controlPacketBurst, "Nftables drop: API IPv6 hashlimit: ", TCP_PROTOCOL_NUMBER, true))
	}

	if icmpPacketLimit > 0 {
		conn.AddRule(createInputRule(chain, intIface.Name, intAddr, nil, icmpPacketLimit, icmpPacketBurst, "Nftables drop: ICMP IPv4 hashlimit: ", ICMP_V4_PROTOCOL_NUMBER, false))
		conn.AddRule(createInputRule(chain, intIface.Name, intAddr, nil, icmpPacketLimit, icmpPacketBurst, "Nftables drop: ICMP IPv6 hashlimit: ", ICMP_V6_PROTOCOL_NUMBER, true))
	}

	if vpnDataLimit > 0 {
		conn.AddRule(createInputRule(chain, intIface.Name, intAddr, nil, vpnDataLimit, vpnDataBurst, "Nftables drop: VPN input IPv4 hashlimit: ", ANY_PROTOCOL_NUMBER, false))
		conn.AddRule(createInputRule(chain, intIface.Name, intAddr, nil, vpnDataLimit, vpnDataBurst, "Nftables drop: VPN input IPv6 hashlimit: ", ANY_PROTOCOL_NUMBER, true))

		conn.AddRule(createInputRule(chain, extIface.Name, extAddr, nil, vpnDataLimit, vpnDataBurst, "Nftables drop: VPN output IPv4 hashlimit: ", ANY_PROTOCOL_NUMBER, false))
		conn.AddRule(createInputRule(chain, extIface.Name, extAddr, nil, vpnDataLimit, vpnDataBurst, "Nftables drop: VPN output IPv6 hashlimit: ", ANY_PROTOCOL_NUMBER, true))
	}

	// Create nftables table forward chain
	dropPolicy := nftables.ChainPolicyDrop
	chain = conn.AddChain(&nftables.Chain{
		Name:     "forward",
		Table:    conf.Nftable,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookForward,
		Priority: nftables.ChainPriorityFilter,
		Policy:   &dropPolicy,
	})

	// Add forward nftables rules
	conn.AddRule(createForwardRule(chain, tunIface, extIface.Name))
	conn.AddRule(createForwardRule(chain, extIface.Name, tunIface))
	conn.AddRule(createLogAndBlockRule(chain, "Nftables drop: prohibited forward: "))

	// Create nftables table postrouting chain
	chain = conn.AddChain(&nftables.Chain{
		Name:     "postrouting",
		Table:    conf.Nftable,
		Type:     nftables.ChainTypeNAT,
		Hooknum:  nftables.ChainHookPostrouting,
		Priority: nftables.ChainPriorityNATSource,
		Policy:   &defaultPolicy,
	})

	// Add masquerade nftables rule
	conn.AddRule(createMasqueradeRule(chain, extIface.Name))

	// Flush nftables
	err = conn.Flush()
	if err != nil {
		return fmt.Errorf("error flushing nftables: %v", err)
	}

	// Return no error
	logrus.Infof("Forwarding configured: %s <-> %s <-> %s", intIface.Name, tunIface, extIface.Name)
	return nil
}

// Restore iptables configuration.
// Use iptables-restore command to restore iptables configurations from bytes.
// Should be applied for TunnelConf object, restore the configurations from .buffer field.
func (conf *TunnelConfig) closeForwarding() error {
	// Create nftables connection
	conn, err := nftables.New()
	if err != nil {
		return fmt.Errorf("error opening nftables connection: %v", err)
	}

	// Remove nftables Seaside table
	if conf.Nftable != nil {
		conn.DelTable(conf.Nftable)
	} else {
		return fmt.Errorf("error deleting nftables table: apparently, it doesn't exist")
	}

	// Flush nftables
	err = conn.Flush()
	if err != nil {
		return fmt.Errorf("error flushing nftables: %v", err)
	}

	return nil
}
