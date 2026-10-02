// Command nas_seed_compiler turns structured, protocol-aware seed specs into
// deterministic raw NAS PDU bytes. It is the "grammar/builder-assisted" seed
// path: callers (e.g. an LLM) describe a message by naming real free5gc/nas
// IEs and short value octets instead of emitting whole-message hex, and this
// program uses the authoritative github.com/free5gc/nas message/ie structs
// (the same ones free5gc itself uses to build UE-side NAS messages) to
// serialize them. Deliberate malformation (TLV length overrides, duplicated
// or reordered IEs, truncation) is applied only after a real, well-formed
// message has been marshaled, and only to IEs this program explicitly set.
//
// Protocol: reads one JSON spec per line on stdin, writes one JSON result per
// line on stdout, in order. A spec that fails to build or mutate produces a
// result with a non-empty "error" and an empty "hex", rather than aborting
// the batch.
package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"reflect"

	"github.com/free5gc/nas/ie"
	"github.com/free5gc/nas/message"
)

// nssaiEntry is one requested S-NSSAI slice.
type nssaiEntry struct {
	SST   uint8  `json:"sst"`
	SDHex string `json:"sd_hex"`
}

// regReqFields covers the subset of 8.2.6 Registration Request IEs this
// compiler can build. A nil/omitted optional pointer field means "do not
// include this IE".
type regReqFields struct {
	RegistrationType      *uint8       `json:"registration_type"`
	MobileIdentityHex     *string      `json:"mobile_identity_hex"`
	SecurityCapabilityHex *string      `json:"security_capability_hex"`
	Capability5GMMHex     *string      `json:"capability_5gmm_hex"`
	NSSAI                 []nssaiEntry `json:"nssai"`
	UplinkDataStatusHex   *string      `json:"uplink_data_status_hex"`
	NASMessageContainer   *string      `json:"nas_message_container_hex"`
}

// pduSessEstReqFields covers 8.3.1 PDU Session Establishment Request IEs.
type pduSessEstReqFields struct {
	PDUSessionID      *uint8  `json:"pdu_session_id"`
	PTI               *uint8  `json:"pti"`
	IntegrityUplink   *uint8  `json:"integrity_uplink"`
	IntegrityDownlink *uint8  `json:"integrity_downlink"`
	PDUSessionType    *string `json:"pdu_session_type"`
	SSCMode           *uint8  `json:"ssc_mode"`
	Capability5GSMHex *string `json:"capability_5gsm_hex"`
	IncludeExtPCO     *bool   `json:"include_extended_pco"`
	ExtPCODNSv4       *bool   `json:"extended_pco_dns_v4"`
	ExtPCODNSv6       *bool   `json:"extended_pco_dns_v6"`
}

type mutation struct {
	Op             string  `json:"op"`
	IE             string  `json:"ie"`
	DeclaredLength *int    `json:"declared_length"`
	AfterBytes     *int    `json:"after_bytes"`
	ValueHex       *string `json:"value_hex"`
}

type seedSpec struct {
	Parser      string          `json:"parser"`
	MessageType string          `json:"message_type"`
	Archetype   string          `json:"archetype"`
	Fields      json.RawMessage `json:"fields"`
	Mutations   []mutation      `json:"mutations"`
	// BaseHex, when non-empty, skips the fields-based builder entirely and
	// instead derives spans directly from these existing wire bytes (Phase
	// 3.2/3.3: splicing an LLM-refined IE value into an AFL queue entry while
	// keeping every other byte, including any prior havoc mutation, intact).
	BaseHex string `json:"base_hex"`
}

type seedResult struct {
	Hex   string `json:"hex"`
	Error string `json:"error"`
}

// ieSpan is a located, named IE inside a marshaled message buffer.
type ieSpan struct {
	name        string
	start       int // offset of the IEI byte
	lengthWidth int // 0 for packed single-byte TV IEs, else 1 or 2
	end         int // one past the last value byte
}

// tlvTableEntry names one optional, length-prefixed IE this compiler knows
// how to locate: its IEI byte and its declared-length field width.
type tlvTableEntry struct {
	name  string
	iei   byte
	width int
}

// regReqTLVTable is shared between building a fresh RegReq (known field
// order) and deriving spans from arbitrary existing bytes (base_hex path,
// Phase 3.2/3.3), where the same fixed free5gc encoding order still holds.
var regReqTLVTable = []tlvTableEntry{
	{"capability_5gmm", message.RegReqIEICapability5GMM, 1},
	{"ue_security_capability", message.RegReqIEIUESecCapability, 1},
	{"requested_nssai", message.RegReqIEIReqNSSAI, 1},
	{"uplink_data_status", message.RegReqIEIUplinkDataStatus, 1},
	{"nas_message_container", message.RegReqIEINASMsgCntr, 2},
}

// registrationRequestHeaderLen derives the mandatory-header length directly
// from wire bytes (EPD+SecHdr+MsgType+packed RegType/Ngksi+MobileId5GS LV-E),
// so spans can be located in a seed this program did not itself build (e.g.
// an AFL++ queue entry) without needing its original build-time fields.
func registrationRequestHeaderLen(buf []byte) (int, error) {
	if len(buf) < 6 {
		return 0, fmt.Errorf("buffer too short for registration_request header (%d bytes)", len(buf))
	}
	mobileIDLen := int(buf[4])<<8 | int(buf[5])
	headerLen := 6 + mobileIDLen
	if len(buf) < headerLen {
		return 0, fmt.Errorf("buffer too short for declared MobileId5GS length %d", mobileIDLen)
	}
	return headerLen, nil
}

func decodeHex(h string) ([]byte, error) {
	if len(h)%2 != 0 {
		return nil, fmt.Errorf("odd-length hex string %q", h)
	}
	out := make([]byte, len(h)/2)
	for i := range out {
		var b int
		if _, err := fmt.Sscanf(h[i*2:i*2+2], "%02x", &b); err != nil {
			return nil, fmt.Errorf("invalid hex byte in %q: %w", h, err)
		}
		out[i] = byte(b)
	}
	return out, nil
}

func buildRegistrationRequest(raw json.RawMessage) ([]byte, []ieSpan, int, error) {
	var fields regReqFields
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &fields); err != nil {
			return nil, nil, 0, fmt.Errorf("decode registration_request fields: %w", err)
		}
	}

	registrationType := uint8(1)
	if fields.RegistrationType != nil {
		registrationType = *fields.RegistrationType
	}

	mobileIdentityHex := "0100f110000000002143f5"
	if fields.MobileIdentityHex != nil {
		mobileIdentityHex = *fields.MobileIdentityHex
	}
	mobileIdentityValue, err := decodeHex(mobileIdentityHex)
	if err != nil {
		return nil, nil, 0, fmt.Errorf("mobile_identity_hex: %w", err)
	}
	mobileIdentity := new(ie.MobileId5GS)
	if err := mobileIdentity.UnmarshalBinary(mobileIdentityValue); err != nil {
		return nil, nil, 0, fmt.Errorf("build MobileId5GS: %w", err)
	}
	mobileIdentityBytes, err := mobileIdentity.MarshalBinary()
	if err != nil {
		return nil, nil, 0, fmt.Errorf("marshal MobileId5GS: %w", err)
	}

	m := &message.RegReq{
		RegType5GS:  &ie.RegType5GS{FOR_Pending: true, Value: registrationType},
		Ngksi:       &ie.NASKeySetId{Tsc: ie.SecCtxTypeNative, Ksi: 0x7},
		MobileId5GS: mobileIdentity,
	}

	// headerLen is the number of bytes written before any optional TLV IE:
	// EPD(1) + SecHdrType(1) + MsgType(1) + packed RegType/Ngksi(1) +
	// MobileId5GS length prefix(2) + MobileId5GS value.
	headerLen := 3 + 1 + 2 + len(mobileIdentityBytes)

	securityCapabilityHex := "8080"
	if fields.SecurityCapabilityHex != nil {
		securityCapabilityHex = *fields.SecurityCapabilityHex
	}
	if securityCapabilityHex != "" {
		value, err := decodeHex(securityCapabilityHex)
		if err != nil {
			return nil, nil, 0, fmt.Errorf("security_capability_hex: %w", err)
		}
		cap := new(ie.UESecCapability)
		if err := cap.UnmarshalBinary(value); err != nil {
			return nil, nil, 0, fmt.Errorf("build UESecCapability: %w", err)
		}
		m.UESecCapability = cap
	}

	capability5GMMHex := "80"
	if fields.Capability5GMMHex != nil {
		capability5GMMHex = *fields.Capability5GMMHex
	}
	if capability5GMMHex != "" {
		value, err := decodeHex(capability5GMMHex)
		if err != nil {
			return nil, nil, 0, fmt.Errorf("capability_5gmm_hex: %w", err)
		}
		cap := new(ie.Capability5GMM)
		if err := cap.UnmarshalBinary(value); err != nil {
			return nil, nil, 0, fmt.Errorf("build Capability5GMM: %w", err)
		}
		m.Capability5GMM = cap
	}

	nssaiEntries := fields.NSSAI
	if nssaiEntries == nil {
		nssaiEntries = []nssaiEntry{{SST: 1, SDHex: "010203"}}
	}
	if len(nssaiEntries) > 0 {
		nssai := &ie.NSSAI{}
		for _, entry := range nssaiEntries {
			nssai.SNSSAIs = append(nssai.SNSSAIs, ie.SNSSAI{SST: entry.SST, SD: entry.SDHex})
		}
		m.ReqNSSAI = nssai
	}

	if fields.UplinkDataStatusHex != nil && *fields.UplinkDataStatusHex != "" {
		value, err := decodeHex(*fields.UplinkDataStatusHex)
		if err != nil {
			return nil, nil, 0, fmt.Errorf("uplink_data_status_hex: %w", err)
		}
		status := new(ie.UplinkDataStatus)
		if err := status.UnmarshalBinary(value); err != nil {
			return nil, nil, 0, fmt.Errorf("build UplinkDataStatus: %w", err)
		}
		m.UplinkDataStatus = status
	}

	if fields.NASMessageContainer != nil && *fields.NASMessageContainer != "" {
		value, err := decodeHex(*fields.NASMessageContainer)
		if err != nil {
			return nil, nil, 0, fmt.Errorf("nas_message_container_hex: %w", err)
		}
		m.NASMsgCntr = &ie.NASMsgCntr{Contents: value}
	}

	out, err := m.MarshalBinary()
	if err != nil {
		return nil, nil, 0, fmt.Errorf("marshal RegReq: %w", err)
	}

	// Known optional TLV IEs this function may have added, in their fixed
	// free5gc encoding order, with (IEI byte -> declared-length width).
	spans, err := walkTLVSpans(out, headerLen, regReqTLVTable)
	if err != nil {
		return nil, nil, 0, err
	}
	return out, spans, headerLen, nil
}

func buildPDUSessionEstablishmentRequest(raw json.RawMessage) ([]byte, []ieSpan, int, error) {
	var fields pduSessEstReqFields
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &fields); err != nil {
			return nil, nil, 0, fmt.Errorf("decode pdu_session_establishment_request fields: %w", err)
		}
	}

	pduSessionID := uint8(1)
	if fields.PDUSessionID != nil {
		pduSessionID = *fields.PDUSessionID
	}
	pti := uint8(0)
	if fields.PTI != nil {
		pti = *fields.PTI
	}
	integrityUplink := uint8(0xff)
	if fields.IntegrityUplink != nil {
		integrityUplink = *fields.IntegrityUplink
	}
	integrityDownlink := uint8(0xff)
	if fields.IntegrityDownlink != nil {
		integrityDownlink = *fields.IntegrityDownlink
	}

	m := &message.PDUSessEstReq{
		PDUSessId: pduSessionID,
		PTI:       pti,
		IntegrityProtectionMaxDataRate: &ie.IntegrityProtectionMaxDataRate{
			Uplink:   integrityUplink,
			Downlink: integrityDownlink,
		},
	}
	// headerLen: EPD(1)+PDUSessId(1)+PTI(1)+MsgType(1)+IntegrityProtectionMaxDataRate(2).
	headerLen := 6

	pduSessionType := "ipv4"
	if fields.PDUSessionType != nil {
		pduSessionType = *fields.PDUSessionType
	}
	pduSessionTypeValues := map[string]uint8{
		"ipv4": ie.PDUSessType_IPv4, "ipv6": ie.PDUSessType_IPv6, "ipv4v6": ie.PDUSessType_IPv4v6,
		"unstructured": ie.PDUSessType_Unstructured, "ethernet": ie.PDUSessType_Ethernet,
	}
	if pduSessionType != "" {
		value, ok := pduSessionTypeValues[pduSessionType]
		if !ok {
			return nil, nil, 0, fmt.Errorf("unknown pdu_session_type %q", pduSessionType)
		}
		m.PDUSessType = &ie.PDUSessType{Value: value}
	}

	sscMode := uint8(ie.SSCMODE1)
	if fields.SSCMode != nil {
		sscMode = *fields.SSCMode
	}
	if sscMode != 0 {
		m.SSCMode = &ie.SSCMode{Mode: sscMode}
	}

	capability5GSMHex := "02"
	if fields.Capability5GSMHex != nil {
		capability5GSMHex = *fields.Capability5GSMHex
	}
	if capability5GSMHex != "" {
		value, err := decodeHex(capability5GSMHex)
		if err != nil {
			return nil, nil, 0, fmt.Errorf("capability_5gsm_hex: %w", err)
		}
		cap := new(ie.Capability5GSM)
		if err := cap.UnmarshalBinary(value); err != nil {
			return nil, nil, 0, fmt.Errorf("build Capability5GSM: %w", err)
		}
		m.Capability5GSM = cap
	}

	includeExtPCO := true
	if fields.IncludeExtPCO != nil {
		includeExtPCO = *fields.IncludeExtPCO
	}
	if includeExtPCO {
		dnsV4, dnsV6 := true, true
		if fields.ExtPCODNSv4 != nil {
			dnsV4 = *fields.ExtPCODNSv4
		}
		if fields.ExtPCODNSv6 != nil {
			dnsV6 = *fields.ExtPCODNSv6
		}
		m.ExtendedProtCfgOpts = &ie.ExtendedProtCfgOpts{
			FromMs: &ie.ExtCfgOptFromMs{DNSV4Req: dnsV4, DNSV6Req: dnsV6},
		}
	}

	out, err := m.MarshalBinary()
	if err != nil {
		return nil, nil, 0, fmt.Errorf("marshal PDUSessEstReq: %w", err)
	}

	spans, err := walkPDUSessEstReqSpans(out, headerLen)
	if err != nil {
		return nil, nil, 0, err
	}
	return out, spans, headerLen, nil
}

// walkTLVSpans scans a buffer of back-to-back standard TLV IEs (1 IEI byte +
// a 1- or 2-byte big-endian declared length + that many value bytes),
// starting at offset, naming each span from table in encounter order. It
// trusts that the caller only ever adds IEs present in table, in free5gc's
// fixed struct-declaration order, so there is no ambiguity.
func walkTLVSpans(buf []byte, offset int, table []tlvTableEntry) ([]ieSpan, error) {
	var spans []ieSpan
	pos := offset
	for pos < len(buf) {
		iei := buf[pos]
		var entry *tlvTableEntry
		for i := range table {
			if table[i].iei == iei {
				entry = &table[i]
				break
			}
		}
		if entry == nil {
			return nil, fmt.Errorf("unrecognized IEI 0x%02x at offset %d; cannot safely locate IE spans", iei, pos)
		}
		if pos+1+entry.width > len(buf) {
			return nil, fmt.Errorf("truncated length field for IE %q at offset %d", entry.name, pos)
		}
		var length int
		if entry.width == 1 {
			length = int(buf[pos+1])
		} else {
			length = int(buf[pos+1])<<8 | int(buf[pos+2])
		}
		end := pos + 1 + entry.width + length
		if end > len(buf) {
			return nil, fmt.Errorf("IE %q declares length past end of buffer", entry.name)
		}
		spans = append(spans, ieSpan{name: entry.name, start: pos, lengthWidth: entry.width, end: end})
		pos = end
	}
	return spans, nil
}

// walkPDUSessEstReqSpans is like walkTLVSpans but also recognizes the two
// packed single-byte TV IEs (PDUSessType, SSCMode) that may precede the TLV
// IEs in a PDU Session Establishment Request.
func walkPDUSessEstReqSpans(buf []byte, offset int) ([]ieSpan, error) {
	var spans []ieSpan
	pos := offset
	tlvTable := []tlvTableEntry{
		{"capability_5gsm", message.PDUSessEstReqIEICapability5GSM, 1},
		{"extended_pco", message.PDUSessEstReqIEIExtendedProtCfgOpts, 2},
	}
	for pos < len(buf) {
		b := buf[pos]
		switch {
		case b&0xF0 == message.PDUSessEstReqIEIPDUSessType:
			spans = append(spans, ieSpan{name: "pdu_session_type", start: pos, lengthWidth: 0, end: pos + 1})
			pos++
			continue
		case b&0xF0 == message.PDUSessEstReqIEISSCMode:
			spans = append(spans, ieSpan{name: "ssc_mode", start: pos, lengthWidth: 0, end: pos + 1})
			pos++
			continue
		}
		var entry *tlvTableEntry
		for i := range tlvTable {
			if tlvTable[i].iei == b {
				entry = &tlvTable[i]
				break
			}
		}
		if entry == nil {
			return nil, fmt.Errorf("unrecognized IEI 0x%02x at offset %d; cannot safely locate IE spans", b, pos)
		}
		if pos+1+entry.width > len(buf) {
			return nil, fmt.Errorf("truncated length field for IE %q at offset %d", entry.name, pos)
		}
		var length int
		if entry.width == 1 {
			length = int(buf[pos+1])
		} else {
			length = int(buf[pos+1])<<8 | int(buf[pos+2])
		}
		end := pos + 1 + entry.width + length
		if end > len(buf) {
			return nil, fmt.Errorf("IE %q declares length past end of buffer", entry.name)
		}
		spans = append(spans, ieSpan{name: entry.name, start: pos, lengthWidth: entry.width, end: end})
		pos = end
	}
	return spans, nil
}

func findSpan(spans []ieSpan, name string) (ieSpan, bool) {
	for _, span := range spans {
		if span.name == name {
			return span, true
		}
	}
	return ieSpan{}, false
}

func applyMutation(buf []byte, spans []ieSpan, headerLen int, mut mutation) ([]byte, []ieSpan, error) {
	switch mut.Op {
	case "truncate":
		if mut.AfterBytes == nil {
			return nil, nil, fmt.Errorf("truncate requires after_bytes")
		}
		n := *mut.AfterBytes
		if n <= 0 || n >= len(buf) {
			return nil, nil, fmt.Errorf("truncate after_bytes=%d out of range for %d-byte message", n, len(buf))
		}
		return append([]byte{}, buf[:n]...), nil, nil

	case "set_ie_length":
		span, ok := findSpan(spans, mut.IE)
		if !ok || span.lengthWidth == 0 {
			return nil, nil, fmt.Errorf("set_ie_length: IE %q not present or not length-prefixed", mut.IE)
		}
		if mut.DeclaredLength == nil {
			return nil, nil, fmt.Errorf("set_ie_length requires declared_length")
		}
		value := *mut.DeclaredLength
		maxValue := 1<<(8*span.lengthWidth) - 1
		if value < 0 || value > maxValue {
			return nil, nil, fmt.Errorf("set_ie_length: declared_length %d out of range for width %d", value, span.lengthWidth)
		}
		out := append([]byte{}, buf...)
		lenOffset := span.start + 1
		if span.lengthWidth == 1 {
			out[lenOffset] = byte(value)
		} else {
			out[lenOffset] = byte(value >> 8)
			out[lenOffset+1] = byte(value)
		}
		return out, spans, nil

	case "duplicate_ie":
		span, ok := findSpan(spans, mut.IE)
		if !ok {
			return nil, nil, fmt.Errorf("duplicate_ie: IE %q not present", mut.IE)
		}
		segment := buf[span.start:span.end]
		out := append([]byte{}, buf[:span.end]...)
		out = append(out, segment...)
		out = append(out, buf[span.end:]...)
		return out, nil, nil

	case "move_ie_to_front":
		span, ok := findSpan(spans, mut.IE)
		if !ok {
			return nil, nil, fmt.Errorf("move_ie_to_front: IE %q not present", mut.IE)
		}
		segment := append([]byte{}, buf[span.start:span.end]...)
		rest := append([]byte{}, buf[:span.start]...)
		rest = append(rest, buf[span.end:]...)
		// Insert right after the mandatory header, i.e. before every other
		// optional IE, not at the IE's old (now-shifted) offset.
		out := append([]byte{}, rest[:headerLen]...)
		out = append(out, segment...)
		out = append(out, rest[headerLen:]...)
		return out, nil, nil

	case "replace_ie_value":
		// Phase 3.2: splice a new value into one IE while leaving every other
		// byte identical. Used to turn a coverage-gap LLM suggestion into a
		// seed that differs from its base only in the targeted IE.
		span, ok := findSpan(spans, mut.IE)
		if !ok {
			return nil, nil, fmt.Errorf("replace_ie_value: IE %q not present", mut.IE)
		}
		if span.lengthWidth == 0 {
			return nil, nil, fmt.Errorf("replace_ie_value: IE %q is a packed TV field, not supported", mut.IE)
		}
		if mut.ValueHex == nil {
			return nil, nil, fmt.Errorf("replace_ie_value requires value_hex")
		}
		newValue, err := decodeHex(*mut.ValueHex)
		if err != nil {
			return nil, nil, fmt.Errorf("replace_ie_value: value_hex: %w", err)
		}
		maxValue := 1<<(8*span.lengthWidth) - 1
		if len(newValue) > maxValue {
			return nil, nil, fmt.Errorf(
				"replace_ie_value: new value is %d bytes, exceeds max %d for a %d-byte length field",
				len(newValue), maxValue, span.lengthWidth,
			)
		}
		valueStart := span.start + 1 + span.lengthWidth
		out := append([]byte{}, buf[:valueStart]...)
		out = append(out, newValue...)
		out = append(out, buf[span.end:]...)
		lenOffset := span.start + 1
		if span.lengthWidth == 1 {
			out[lenOffset] = byte(len(newValue))
		} else {
			out[lenOffset] = byte(len(newValue) >> 8)
			out[lenOffset+1] = byte(len(newValue))
		}
		// The new value's length may differ from the old one, shifting every
		// later span; the caller gets no more mutations after this in
		// practice (coverage-gap specs use exactly one), so invalidating
		// spans here is consistent with duplicate_ie/move_ie_to_front.
		return out, nil, nil

	default:
		return nil, nil, fmt.Errorf("unknown mutation op %q", mut.Op)
	}
}

func compileSpec(spec seedSpec) ([]byte, error) {
	var (
		buf       []byte
		spans     []ieSpan
		headerLen int
		err       error
	)
	if spec.BaseHex != "" {
		buf, err = decodeHex(spec.BaseHex)
		if err != nil {
			return nil, fmt.Errorf("base_hex: %w", err)
		}
		switch spec.MessageType {
		case "registration_request":
			if spec.Parser != "gmm" {
				return nil, fmt.Errorf("registration_request requires parser=gmm, got %q", spec.Parser)
			}
			headerLen, err = registrationRequestHeaderLen(buf)
			if err != nil {
				return nil, fmt.Errorf("base_hex: %w", err)
			}
			spans, err = walkTLVSpans(buf, headerLen, regReqTLVTable)
		case "pdu_session_establishment_request":
			if spec.Parser != "gsm" {
				return nil, fmt.Errorf("pdu_session_establishment_request requires parser=gsm, got %q", spec.Parser)
			}
			if len(buf) < 6 {
				return nil, fmt.Errorf("base_hex too short for pdu_session_establishment_request header (%d bytes)", len(buf))
			}
			headerLen = 6
			spans, err = walkPDUSessEstReqSpans(buf, headerLen)
		default:
			return nil, fmt.Errorf("unknown message_type %q", spec.MessageType)
		}
		if err != nil {
			return nil, fmt.Errorf("deriving IE spans from base_hex: %w", err)
		}
	} else {
		switch spec.MessageType {
		case "registration_request":
			if spec.Parser != "gmm" {
				return nil, fmt.Errorf("registration_request requires parser=gmm, got %q", spec.Parser)
			}
			buf, spans, headerLen, err = buildRegistrationRequest(spec.Fields)
		case "pdu_session_establishment_request":
			if spec.Parser != "gsm" {
				return nil, fmt.Errorf("pdu_session_establishment_request requires parser=gsm, got %q", spec.Parser)
			}
			buf, spans, headerLen, err = buildPDUSessionEstablishmentRequest(spec.Fields)
		default:
			return nil, fmt.Errorf("unknown message_type %q", spec.MessageType)
		}
		if err != nil {
			return nil, err
		}
	}

	for _, mut := range spec.Mutations {
		buf, spans, err = applyMutation(buf, spans, headerLen, mut)
		if err != nil {
			return nil, fmt.Errorf("archetype %q mutation %+v: %w", spec.Archetype, mut, err)
		}
	}
	return buf, nil
}

func main() {
	mode := "compile"
	if len(os.Args) > 1 {
		mode = os.Args[1]
	}
	switch mode {
	case "compile":
		runCompileLoop()
	case "dissect":
		runDissectLoop()
	default:
		fmt.Fprintf(os.Stderr, "unknown mode %q; expected \"compile\" or \"dissect\"\n", mode)
		os.Exit(2)
	}
}

func runCompileLoop() {
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	out := bufio.NewWriter(os.Stdout)
	defer out.Flush()

	for scanner.Scan() {
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			continue
		}
		var spec seedSpec
		var result seedResult
		if err := json.Unmarshal(line, &spec); err != nil {
			result.Error = fmt.Sprintf("invalid spec JSON: %v", err)
		} else if raw, err := compileSpec(spec); err != nil {
			result.Error = err.Error()
		} else {
			result.Hex = fmt.Sprintf("%x", raw)
		}
		encoded, err := json.Marshal(result)
		if err != nil {
			fmt.Fprintf(os.Stderr, "internal: marshal result: %v\n", err)
			os.Exit(1)
		}
		out.Write(encoded)
		out.WriteByte('\n')
	}
	if err := scanner.Err(); err != nil {
		fmt.Fprintf(os.Stderr, "reading stdin: %v\n", err)
		os.Exit(1)
	}
}

// dissectRequest names a candidate seed to feed through the real free5gc/nas
// parser (Phase 3.2: "parse candidate seeds with your dissector").
type dissectRequest struct {
	Parser string `json:"parser"`
	Hex    string `json:"hex"`
}

// dissectResult reports, in order of preference: on success, which IEs the
// parser actually populated (named by their Go struct field, e.g.
// "UESecCapability"); on failure, free5gc's own error string, which in this
// codebase is already wrapped with the failing IE's field name (e.g.
// "RegReq.UESecCapability.UnmarshalBinary: ..."). Both are directly usable as
// the "reached X" / "failed at Y" context for coverage-gap prompting.
type dissectResult struct {
	OK              bool              `json:"ok"`
	MessageType     string            `json:"message_type,omitempty"`
	ReachedIEs      []string          `json:"reached_ies,omitempty"`
	MutableIEValues map[string]string `json:"mutable_ie_values,omitempty"`
	Error           string            `json:"error,omitempty"`
}

func runDissectLoop() {
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	out := bufio.NewWriter(os.Stdout)
	defer out.Flush()

	for scanner.Scan() {
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			continue
		}
		var request dissectRequest
		var result dissectResult
		if err := json.Unmarshal(line, &request); err != nil {
			result.Error = fmt.Sprintf("invalid request JSON: %v", err)
		} else {
			result = dissect(request)
		}
		encoded, err := json.Marshal(result)
		if err != nil {
			fmt.Fprintf(os.Stderr, "internal: marshal result: %v\n", err)
			os.Exit(1)
		}
		out.Write(encoded)
		out.WriteByte('\n')
	}
	if err := scanner.Err(); err != nil {
		fmt.Fprintf(os.Stderr, "reading stdin: %v\n", err)
		os.Exit(1)
	}
}

func dissect(request dissectRequest) dissectResult {
	raw, err := decodeHex(request.Hex)
	if err != nil {
		return dissectResult{Error: fmt.Sprintf("invalid hex: %v", err)}
	}
	switch request.Parser {
	case "gmm":
		parsed, parseErr := message.ParseGMM(raw)
		if parseErr != nil {
			return dissectResult{OK: false, Error: parseErr.Error()}
		}
		msgType, reached := inspectParsedMessage(parsed)
		result := dissectResult{OK: true, MessageType: msgType, ReachedIEs: reached}
		if msgType == "RegReq" {
			if headerLen, err := registrationRequestHeaderLen(raw); err == nil {
				if spans, err := walkTLVSpans(raw, headerLen, regReqTLVTable); err == nil {
					result.MutableIEValues = ieValueHexMap(raw, spans)
				}
			}
		}
		return result
	case "gsm":
		parsed, parseErr := message.ParseGSM(raw)
		if parseErr != nil {
			return dissectResult{OK: false, Error: parseErr.Error()}
		}
		msgType, reached := inspectParsedMessage(parsed)
		result := dissectResult{OK: true, MessageType: msgType, ReachedIEs: reached}
		if msgType == "PDUSessEstReq" {
			if spans, err := walkPDUSessEstReqSpans(raw, 6); err == nil {
				result.MutableIEValues = ieValueHexMap(raw, spans)
			}
		}
		return result
	default:
		return dissectResult{Error: fmt.Sprintf("unknown parser %q", request.Parser)}
	}
}

// ieValueHexMap extracts each named IE's current value bytes (excluding its
// IEI/length prefix), skipping packed single-byte TV fields (lengthWidth 0)
// which replace_ie_value cannot target. Used to seed coverage-gap prompts
// with a real "current value" without the caller re-deriving spans itself.
func ieValueHexMap(buf []byte, spans []ieSpan) map[string]string {
	values := map[string]string{}
	for _, span := range spans {
		if span.lengthWidth == 0 {
			continue
		}
		valueStart := span.start + 1 + span.lengthWidth
		values[span.name] = fmt.Sprintf("%x", buf[valueStart:span.end])
	}
	return values
}

// inspectParsedMessage reports the concrete message type name and the names
// of every optional-IE field free5gc actually populated (non-nil pointer or
// non-empty slice), regardless of which of the ~30 message.* structs
// ParseGMM/ParseGSM happened to return for this input's message-type byte.
func inspectParsedMessage(parsed any) (string, []string) {
	value := reflect.ValueOf(parsed)
	if value.Kind() == reflect.Ptr {
		if value.IsNil() {
			return "", nil
		}
		value = value.Elem()
	}
	if value.Kind() != reflect.Struct {
		return "", nil
	}
	typ := value.Type()
	var reached []string
	for i := 0; i < value.NumField(); i++ {
		field := value.Field(i)
		switch field.Kind() {
		case reflect.Ptr, reflect.Interface:
			if !field.IsNil() {
				reached = append(reached, typ.Field(i).Name)
			}
		case reflect.Slice:
			if field.Len() > 0 {
				reached = append(reached, typ.Field(i).Name)
			}
		}
	}
	return typ.Name(), reached
}
