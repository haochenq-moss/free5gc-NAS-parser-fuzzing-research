package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/free5gc/nas/ie"
	nasmessage "github.com/free5gc/nas/message"
	"github.com/free5gc/ngap/aper"
	ngapie "github.com/free5gc/ngap/ie"
	ngapmessage "github.com/free5gc/ngap/message"
	"github.com/free5gc/sctp"
)

const (
	amfIP       = "10.0.1.1"
	amfPort     = 38412
	localIP     = "10.0.1.1"
	ngapPPID    = 0x3c000000
	syntheticID = "208930000000002"
	gnbID       = 0x000315
	ranUEID     = 0x7fff15
	maxPDUBytes = 4096
)

type report struct {
	Case                 string `json:"case"`
	SUPI                 string `json:"synthetic_supi"`
	PDUHex               string `json:"pdu_hex"`
	PDUBytes             int    `json:"pdu_bytes"`
	SHA256               string `json:"pdu_sha256"`
	AMF                  string `json:"amf"`
	NGSetup              string `json:"ng_setup"`
	NASResponse          string `json:"nas_response"`
	RegistrationReject   *uint8 `json:"registration_reject_cause,omitempty"`
	AMFContextRelease     string `json:"amf_context_release"`
	NetworkReplayPerformed bool   `json:"network_replay_performed"`
}

func main() {
	execute := flag.Bool("execute", false, "send one PDU to the fixed isolated AMF")
	confirm := flag.Bool("confirm-isolated-testbed", false, "assert this is the authorized private lab")
	flag.Parse()

	pdu, err := candidatePDU()
	if err != nil {
		fatal(err)
	}
	digest := sha256.Sum256(pdu)
	result := report{
		Case: "gmm_security_capability_cut_mid_value",
		SUPI: syntheticID,
		PDUHex: hex.EncodeToString(pdu),
		PDUBytes: len(pdu),
		SHA256: hex.EncodeToString(digest[:]),
		AMF: net.JoinHostPort(amfIP, fmt.Sprint(amfPort)),
		NGSetup: "not_attempted",
		NASResponse: "not_attempted",
		AMFContextRelease: "not_attempted",
	}
	if len(pdu) > maxPDUBytes {
		fatal(errors.New("candidate exceeds the fixed 4096-byte limit"))
	}
	if !*execute {
		writeReport(result)
		return
	}
	if !*confirm {
		fatal(errors.New("live mode requires --confirm-isolated-testbed"))
	}
	if err := executeOne(pdu, &result); err != nil {
		result.AMFContextRelease = "unconfirmed: " + err.Error()
		writeReport(result)
		os.Exit(1)
	}
	writeReport(result)
}

func candidatePDU() ([]byte, error) {
	mobileIdentity := new(ie.MobileId5GS)
	identityBytes, err := hex.DecodeString("0102f83900000000000000f2")
	if err != nil {
		return nil, err
	}
	if err := mobileIdentity.UnmarshalBinary(identityBytes); err != nil {
		return nil, fmt.Errorf("decode fixed synthetic mobile identity: %w", err)
	}
	securityCapability := new(ie.UESecCapability)
	if err := securityCapability.UnmarshalBinary([]byte{0x78, 0x78}); err != nil {
		return nil, fmt.Errorf("decode fixed security capability: %w", err)
	}
	message := &nasmessage.RegReq{
		RegType5GS: &ie.RegType5GS{FOR_Pending: true, Value: ie.RegType_InitialReg},
		Ngksi: &ie.NASKeySetId{Tsc: ie.SecCtxTypeNative, Ksi: ie.NASKeyNA},
		MobileId5GS: mobileIdentity,
		UESecCapability: securityCapability,
		Capability5GMM: &ie.Capability5GMM{Length: 1, SGC: true},
	}
	pdu, err := message.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("marshal fixed registration request: %w", err)
	}
	for offset := 0; offset+3 < len(pdu); offset++ {
		if pdu[offset] == 0x2e && pdu[offset+1] == 2 && pdu[offset+2] == 0x78 && pdu[offset+3] == 0x78 {
			pdu[offset+1] = 4
			return pdu, nil
		}
	}
	return nil, errors.New("could not locate the fixed UE security capability IE")
}

func executeOne(pdu []byte, result *report) error {
	remote := &sctp.SCTPAddr{IPAddrs: []net.IPAddr{{IP: net.ParseIP(amfIP)}}, Port: amfPort}
	local := &sctp.SCTPAddr{IPAddrs: []net.IPAddr{{IP: net.ParseIP(localIP)}}, Port: 0}
	conn, err := sctp.DialSCTP("sctp", local, remote)
	if err != nil {
		return fmt.Errorf("connect to configured private AMF: %w", err)
	}
	defer conn.Close()
	params, err := conn.GetDefaultSentParam()
	if err != nil {
		return fmt.Errorf("read SCTP send parameters: %w", err)
	}
	params.PPID = ngapPPID
	if err := conn.SetDefaultSentParam(params); err != nil {
		return fmt.Errorf("set NGAP SCTP PPID: %w", err)
	}

	setup, err := buildNGSetupRequest()
	if err != nil {
		return fmt.Errorf("build test gNB NG Setup: %w", err)
	}
	if _, err := conn.Write(setup); err != nil {
		return fmt.Errorf("send test gNB NG Setup: %w", err)
	}
	firstResponse, err := readNGAP(conn)
	if err != nil {
		return fmt.Errorf("read NG Setup response: %w", err)
	}
	if firstResponse.ProcedureCode() != ngapmessage.ProcedureCodeNGSetup || firstResponse.MessageType() != ngapmessage.MessageTypeSuccessfulOutcome {
		return fmt.Errorf("AMF did not accept test gNB NG Setup (procedure=%d type=%d)", firstResponse.ProcedureCode(), firstResponse.MessageType())
	}
	result.NGSetup = "accepted"

	initial, err := buildInitialUEMessage(pdu)
	if err != nil {
		return fmt.Errorf("build one InitialUEMessage: %w", err)
	}
	if _, err := conn.Write(initial); err != nil {
		return fmt.Errorf("send the single candidate PDU: %w", err)
	}
	result.NetworkReplayPerformed = true
	downlink, err := readNGAP(conn)
	if err != nil {
		return fmt.Errorf("read the one NAS response: %w", err)
	}
	if downlink.ProcedureCode() != ngapmessage.ProcedureCodeDownlinkNASTransport {
		return fmt.Errorf("AMF returned unexpected NGAP procedure %d", downlink.ProcedureCode())
	}
	transport, ok := downlink.(*ngapmessage.DownlinkNASTransport)
	if !ok || transport.NASPDU == nil || transport.AMFUENGAPID == nil || transport.RANUENGAPID == nil {
		return errors.New("AMF downlink did not contain a complete NAS transport")
	}
	response, err := nasmessage.ParseGMM([]byte(transport.NASPDU.Value))
	if err != nil {
		return fmt.Errorf("decode NAS response type only: %w", err)
	}
	switch typed := response.(type) {
	case *nasmessage.RegRej:
		result.NASResponse = "registration_reject"
		if typed.Cause5GMM != nil {
			cause := typed.Cause5GMM.Value
			result.RegistrationReject = &cause
		}
	case *nasmessage.AuthReq:
		result.NASResponse = "authentication_request"
	default:
		result.NASResponse = fmt.Sprintf("nas_message_%T", response)
	}

	if err := requestAMFContextRelease(conn, transport.AMFUENGAPID.Value, transport.RANUENGAPID.Value); err != nil {
		return fmt.Errorf("candidate responded but AMF context release was not confirmed: %w", err)
	}
	result.AMFContextRelease = "complete_received"
	return nil
}

func readNGAP(conn *sctp.SCTPConn) (ngapmessage.Message, error) {
	timer := time.AfterFunc(8*time.Second, func() {
		_ = conn.Close()
	})
	defer timer.Stop()
	buffer := make([]byte, 8192)
	n, err := conn.Read(buffer)
	if err != nil {
		return nil, err
	}
	return ngapmessage.Parse(buffer[:n])
}

func buildNGSetupRequest() ([]byte, error) {
	plmn := aper.OctetString{0x02, 0xf8, 0x39}
	request := &ngapmessage.NGSetupRequest{
		GlobalRANNodeID: &ngapie.GlobalRANNodeID{Choice: &ngapie.GlobalGNBID{
			PLMNIdentity: &ngapie.PLMNIdentity{Value: plmn},
			GNBID: &ngapie.GNBID{Choice: &ngapie.GNBIDForGNBID{Value: aper.BitString{
				Bytes: []byte{0x00, 0x03, 0x15}, BitLength: 24,
			}}},
		}},
		RANNodeName: &ngapie.RANNodeName{Value: aper.PrintableString("nas-fuzz-probe-000315")},
		SupportedTAList: &ngapie.SupportedTAList{List: []ngapie.SupportedTAItem{{
			TAC: &ngapie.TAC{Value: aper.OctetString{0x00, 0x00, 0x01}},
			BroadcastPLMNList: &ngapie.BroadcastPLMNList{List: []ngapie.BroadcastPLMNItem{{
				PLMNIdentity: &ngapie.PLMNIdentity{Value: plmn},
				TAISliceSupportList: &ngapie.SliceSupportList{List: []ngapie.SliceSupportItem{{
					SNSSAI: &ngapie.SNSSAI{SST: &ngapie.SST{Value: aper.OctetString{0x01}}, SD: &ngapie.SD{Value: aper.OctetString{0x01, 0x02, 0x03}}},
				}}},
			}}},
		}}},
		DefaultPagingDRX: &ngapie.PagingDRX{Value: ngapie.PagingDRXPresentV128},
	}
	return request.MarshalBinary()
}

func buildInitialUEMessage(pdu []byte) ([]byte, error) {
	plmn := aper.OctetString{0x02, 0xf8, 0x39}
	request := &ngapmessage.InitialUEMessage{
		RANUENGAPID: &ngapie.RANUENGAPID{Value: ranUEID},
		NASPDU: &ngapie.NASPDU{Value: aper.OctetString(pdu)},
		UserLocationInformation: &ngapie.UserLocationInformation{Choice: &ngapie.UserLocationInformationNR{
			NRCGI: &ngapie.NRCGI{
				PLMNIdentity: &ngapie.PLMNIdentity{Value: plmn},
				NRCellIdentity: &ngapie.NRCellIdentity{Value: aper.BitString{Bytes: []byte{0x00, 0x03, 0x15, 0x00, 0x10}, BitLength: 36}},
			},
			TAI: &ngapie.TAI{PLMNIdentity: &ngapie.PLMNIdentity{Value: plmn}, TAC: &ngapie.TAC{Value: aper.OctetString{0x00, 0x00, 0x01}}},
		}},
		RRCEstablishmentCause: &ngapie.RRCEstablishmentCause{Value: ngapie.RRCEstablishmentCausePresentMoSignalling},
	}
	return request.MarshalBinary()
}

func requestAMFContextRelease(conn *sctp.SCTPConn, amfID, ranID int64) error {
	request := &ngapmessage.UEContextReleaseRequest{
		AMFUENGAPID: &ngapie.AMFUENGAPID{Value: amfID},
		RANUENGAPID: &ngapie.RANUENGAPID{Value: ranID},
		Cause: &ngapie.Cause{Choice: &ngapie.CauseRadioNetwork{Value: ngapie.CauseRadioNetworkPresentUserInactivity}},
	}
	encoded, err := request.MarshalBinary()
	if err != nil {
		return fmt.Errorf("encode UE context release request: %w", err)
	}
	if _, err := conn.Write(encoded); err != nil {
		return fmt.Errorf("send UE context release request: %w", err)
	}
	command, err := readNGAP(conn)
	if err != nil {
		return fmt.Errorf("read UE context release command: %w", err)
	}
	if command.ProcedureCode() != ngapmessage.ProcedureCodeUEContextRelease || command.MessageType() != ngapmessage.MessageTypeInitiatingMessage {
		return fmt.Errorf("unexpected response while releasing context (procedure=%d type=%d)", command.ProcedureCode(), command.MessageType())
	}
	complete := &ngapmessage.UEContextReleaseComplete{
		AMFUENGAPID: &ngapie.AMFUENGAPID{Value: amfID},
		RANUENGAPID: &ngapie.RANUENGAPID{Value: ranID},
	}
	completeBytes, err := complete.MarshalBinary()
	if err != nil {
		return fmt.Errorf("encode UE context release complete: %w", err)
	}
	if _, err := conn.Write(completeBytes); err != nil {
		return fmt.Errorf("send UE context release complete: %w", err)
	}
	return nil
}

func writeReport(value report) {
	_ = json.NewEncoder(os.Stdout).Encode(value)
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "error:", err)
	os.Exit(2)
}