package context

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"sync"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/free5gc/amf/internal/logger"
	business_metrics "github.com/free5gc/amf/internal/metrics/business"
	"github.com/free5gc/amf/pkg/factory"
	"github.com/free5gc/nas/ie"
	"github.com/free5gc/nas/message"
	"github.com/free5gc/openapi"
	"github.com/free5gc/openapi/models"
	"github.com/free5gc/util/fsm"
	"github.com/free5gc/util/idgenerator"
	"github.com/free5gc/util/ueauth"
)

type OnGoingProcedure string

const (
	OnGoingProcedureNothing      OnGoingProcedure = "Nothing"
	OnGoingProcedurePaging       OnGoingProcedure = "Paging"
	OnGoingProcedureN2Handover   OnGoingProcedure = "N2Handover"
	OnGoingProcedureRegistration OnGoingProcedure = "Registration"
)

const (
	NgRanCgiPresentNRCGI    int32 = 0
	NgRanCgiPresentEUTRACGI int32 = 1
)

const (
	RecommendRanNodePresentRanNode int32 = 0
	RecommendRanNodePresentTAI     int32 = 1
)

// GMM state for UE
const (
	Deregistered            fsm.StateType = "Deregistered"
	DeregistrationInitiated fsm.StateType = "DeregistrationInitiated"
	Authentication          fsm.StateType = "Authentication"
	SecurityMode            fsm.StateType = "SecurityMode"
	ContextSetup            fsm.StateType = "ContextSetup"
	Registered              fsm.StateType = "Registered"
)

type AmfUe struct {
	/* the AMF which serving this AmfUe now */
	servingAMF *AMFContext // never nil

	/* Gmm State */
	State map[models.AccessType]*fsm.State
	/* Registration procedure related context */
	RegistrationType5GS                uint8
	IdentityTypeUsedForRegistration    uint8
	RegistrationRequest                *message.RegReq
	ServingAmfChanged                  bool
	DeregistrationTargetAccessType     uint8 // only used when deregistration procedure is initialized by the network
	RegistrationAcceptForNon3GPPAccess []byte
	NasPduValue                        []byte
	RetransmissionOfInitialNASMsg      bool
	RequestIdentityType                uint8
	/* Used for AMF relocation */
	TargetAmfProfile *models.Nrf_NFDisc_NFProfile
	TargetAmfUri     string
	/* Ue Identity */
	PlmnId                 models.PlmnId
	Suci                   string
	Supi                   string
	UnauthenticatedSupi    bool
	Gpsi                   string
	Pei                    string
	Tmsi                   int32 // 5G-Tmsi
	Guti                   string
	GroupID                string
	EBI                    int32
	EventSubscriptionsInfo map[string]*AmfUeEventSubscription
	/* User Location */
	RatType                  models.RatType
	Location                 models.UserLocation
	Tai                      models.Tai
	LocationChanged          bool
	LastVisitedRegisteredTai models.Tai
	TimeZone                 string // "[+-]HH:MM[+][1-2]", Refer to TS 29.571 - 5.2.2 Simple Data Types
	/* context about udm */
	UdmId                             string
	NudmUECMUri                       string
	NudmSDMUri                        string
	ContextValid                      bool
	Reachability                      models.Amf_EvtExpos_UeReachability
	SmfSelectionData                  *models.Udm_SDM_SmfSelectionSubscriptionData
	UeContextInSmfData                *models.Udm_SDM_UeContextInSmfData
	TraceData                         *models.TraceData
	UdmGroupId                        string
	SubscribedNssai                   []models.Nssf_NSSel_SubscribedSnssai
	AccessAndMobilitySubscriptionData *models.Udm_SDM_AccessAndMobilitySubscriptionData
	BackupAmfInfo                     []models.BackupAmfInfo
	/* contex abut ausf */
	AusfGroupId                       string
	AusfId                            string
	AusfUri                           string
	RoutingIndicator                  string
	AuthenticationCtx                 *models.Ausf_UEAU_UEAuthenticationCtx
	AuthFailureCauseSynchFailureTimes int
	IdentityRequestSendTimes          int
	ABBA                              []uint8
	Kseaf                             string
	Kamf                              string
	/* context about PCF */
	PcfId                        string
	PcfUri                       string
	PolicyAssociationId          string
	AmPolicyUri                  string
	AmPolicyAssociation          *models.Pcf_AMPolCtrl_PolicyAssociation
	RequestTriggerLocationChange bool // true if AmPolicyAssociation.Trigger contains RequestTrigger_LOC_CH
	/* UeContextForHandover */
	HandoverNotifyUri string
	/* N1N2Message */
	N1N2MessageIDGenerator          *idgenerator.IDGenerator
	N1N2Message                     *N1N2Message
	N1N2MessageSubscribeIDGenerator *idgenerator.IDGenerator
	// map[int64]models.Amf_Comm_UeN1N2InfoSubscriptionCreateData; use n1n2MessageSubscriptionID as key
	N1N2MessageSubscription sync.Map
	/* Pdu Sesseion context */
	SmContextList sync.Map // map[int32]*SmContext, pdu session id as key
	/* Related Context */
	RanUe map[models.AccessType]*RanUe
	/* other */
	onGoing                         map[models.AccessType]*OnGoing
	UeRadioCapability               string // OCTET string
	Capability5GMM                  ie.Capability5GMM
	ConfigurationUpdateIndication   ie.CfgUpdateInd
	ConfigurationUpdateCommandFlags *ConfigurationUpdateCommandFlags
	/* context related to Paging */
	UeRadioCapabilityForPaging                 *UERadioCapabilityForPaging
	InfoOnRecommendedCellsAndRanNodesForPaging *InfoOnRecommendedCellsAndRanNodesForPaging
	UESpecificDRX                              uint8
	/* Security Context */
	SecurityContextAvailable bool
	UESecurityCapability     ie.UESecCapability // for security command
	NgKsi                    models.Amf_Comm_NgKsi
	MacFailed                bool      // set to true if the integrity check of current NAS message is failed
	KnasInt                  [16]uint8 // 16 byte
	KnasEnc                  [16]uint8 // 16 byte
	Kgnb                     []uint8   // 32 byte
	Kn3iwf                   []uint8   // 32 byte
	NH                       []uint8   // 32 byte
	NCC                      uint8     // 0..7
	ULCount                  message.Count
	DLCount                  message.Count
	CipheringAlg             uint8
	IntegrityAlg             uint8
	/* Registration Area */
	RegistrationArea map[models.AccessType][]models.Tai
	LadnInfo         []factory.Ladn
	/* Network Slicing related context and Nssf */
	NssfId                            string
	NssfUri                           string
	NetworkSliceInfo                  *models.Nssf_NSSel_AuthorizedNetworkSliceInfo
	AllowedNssai                      map[models.AccessType][]models.Nssf_NSSel_AllowedSnssai
	ConfiguredNssai                   []models.Nssf_NSSel_ConfiguredSnssai
	NetworkSlicingSubscriptionChanged bool
	SdmSubscriptionId                 string
	UeCmRegistered                    map[models.AccessType]bool
	/* T3513(Paging) */
	T3513 *Timer // for paging
	/* T3565(Notification) */
	T3565 *Timer // for NAS Notification
	/* T3560 (for authentication request/security mode command retransmission) */
	T3560 *Timer
	/* T3550 (for registration accept retransmission) */
	T3550 *Timer
	/* T3522 (for deregistration request) */
	T3522 *Timer
	/* T3570 (for identity request) */
	T3570 *Timer
	/* T3555 (for configuration update command) */
	T3555 *Timer
	/* Ue Context Release Cause */
	ReleaseCause map[models.AccessType]*CauseAll
	/* T3502 (Assigned by AMF, and used by UE to initialize registration procedure) */
	T3502Value             int        // Second
	T3512Value             int        // default 54 min
	Non3gppDeregTimerValue int        // default 54 min
	Lock                   sync.Mutex // Update context to prevent race condition
	// RanUeMu serializes access to RanUe and AnTypeFlags.  It is kept separate
	// from Lock because Lock is held by procedures that may enter the RanUe
	// release path.  Hold it only for the map/flag update itself (and, when an
	// attach replaces a RanUe, the stop of the 5GMM timers, which does no I/O),
	// never across NGAP or SBI I/O.
	RanUeMu sync.RWMutex
	// timerMu serializes the T3513..T3570 fields above.  A timer is started by
	// a NAS/NGAP procedure, stopped by another procedure or a release, and
	// cleared by its own goroutine, each on a different goroutine.  Only the
	// field update is done under the lock; Timer.Stop is called after it.
	timerMu sync.Mutex
	// onGoingMu serializes the onGoing map and the OnGoing values it holds.
	onGoingMu sync.RWMutex
	// identityMu serializes Suci: AmfUeFindBySuci scans the UE pool from an
	// NGAP worker while a GMM handler records the SUCI on another goroutine.
	identityMu sync.RWMutex

	// logger
	NASLog      *logrus.Entry
	GmmLog      *logrus.Entry
	ProducerLog *logrus.Entry

	// Metrics related
	GmmStateEnterTime time.Time
	UeConnected       bool
	AnTypeFlags       map[models.AccessType]bool
}

type AmfUeEventSubscription struct {
	Timestamp         time.Time
	AnyUe             bool
	RemainReports     *int32
	EventSubscription *models.Amf_Comm_ExtAmfEventSubscription
}

type N1N2Message struct {
	Request     models.N1N2MessageTransferRequestBody
	Status      models.Amf_Comm_N1N2MessageTransferCause
	ResourceUri string
}

type OnGoing struct {
	Procedure OnGoingProcedure
	Ppi       int32 // Paging priority
}

type UERadioCapabilityForPaging struct {
	NR    string // OCTET string
	EUTRA string // OCTET string
}

// TS 38.413 9.3.1.100
type InfoOnRecommendedCellsAndRanNodesForPaging struct {
	RecommendedCells    []RecommendedCell  // RecommendedCellsForPaging
	RecommendedRanNodes []RecommendRanNode // RecommendedRanNodesForPaging
}

// TS 38.413 9.3.1.71
type RecommendedCell struct {
	NgRanCGI         NGRANCGI
	TimeStayedInCell *int64
}

// TS 38.413 9.3.1.101
type RecommendRanNode struct {
	Present         int32
	GlobalRanNodeId *models.GlobalRanNodeId
	Tai             *models.Tai
}

type NGRANCGI struct {
	Present  int32
	NRCGI    *models.Ncgi
	EUTRACGI *models.Ecgi
}

// TS 24.501 8.2.19
type ConfigurationUpdateCommandFlags struct {
	NeedGUTI                                     bool
	NeedNITZ                                     bool
	NeedTaiList                                  bool
	NeedRejectNSSAI                              bool
	NeedAllowedNSSAI                             bool
	NeedSmsIndication                            bool
	NeedMicoIndication                           bool
	NeedLadnInformation                          bool
	NeedServiceAreaList                          bool
	NeedConfiguredNSSAI                          bool
	NeedNetworkSlicingIndication                 bool
	NeedOperatordefinedAccessCategoryDefinitions bool
}

func (ue *AmfUe) init() {
	ue.servingAMF = GetSelf()
	ue.State = make(map[models.AccessType]*fsm.State)
	ue.State[models.AccessType_3_GPP_ACCESS] = fsm.NewState(Deregistered)
	ue.State[models.AccessType_NON_3_GPP_ACCESS] = fsm.NewState(Deregistered)
	ue.UnauthenticatedSupi = true
	ue.EventSubscriptionsInfo = make(map[string]*AmfUeEventSubscription)
	ue.RanUe = make(map[models.AccessType]*RanUe)
	ue.RegistrationArea = make(map[models.AccessType][]models.Tai)
	ue.AllowedNssai = make(map[models.AccessType][]models.Nssf_NSSel_AllowedSnssai)
	ue.N1N2MessageIDGenerator = idgenerator.NewGenerator(1, 2147483647)
	ue.N1N2MessageSubscribeIDGenerator = idgenerator.NewGenerator(1, 2147483647)
	ue.onGoing = make(map[models.AccessType]*OnGoing)
	ue.onGoing[models.AccessType_NON_3_GPP_ACCESS] = new(OnGoing)
	ue.onGoing[models.AccessType_NON_3_GPP_ACCESS].Procedure = OnGoingProcedureNothing
	ue.onGoing[models.AccessType_3_GPP_ACCESS] = new(OnGoing)
	ue.onGoing[models.AccessType_3_GPP_ACCESS].Procedure = OnGoingProcedureNothing
	ue.ReleaseCause = make(map[models.AccessType]*CauseAll)
	ue.UeCmRegistered = make(map[models.AccessType]bool)
	ue.GmmLog = logger.GmmLog
	ue.NASLog = logger.GmmLog
	ue.ProducerLog = logger.ProducerLog
	ue.AnTypeFlags = make(map[models.AccessType]bool)
}

func (ue *AmfUe) ServingAMF() *AMFContext {
	return ue.servingAMF
}

// GetSuci returns the SUCI recorded for the UE.
func (ue *AmfUe) GetSuci() string {
	ue.identityMu.RLock()
	defer ue.identityMu.RUnlock()
	return ue.Suci
}

// SetSuci records the SUCI received from the UE.
func (ue *AmfUe) SetSuci(suci string) {
	ue.identityMu.Lock()
	defer ue.identityMu.Unlock()
	ue.Suci = suci
}

func (ue *AmfUe) CmConnect(anType models.AccessType) bool {
	return ue.GetRanUe(anType) != nil
}

// GetRanUe returns the RanUe attached for an access type.  The map read is
// serialized with every attach and detach through RanUeMu, so it can be used
// from the GMM and SBI procedures that run on different goroutines than the
// NGAP worker which owns the RanUe.
func (ue *AmfUe) GetRanUe(anType models.AccessType) *RanUe {
	ue.RanUeMu.RLock()
	defer ue.RanUeMu.RUnlock()
	return ue.RanUe[anType]
}

func (ue *AmfUe) CmIdle(anType models.AccessType) bool {
	return !ue.CmConnect(anType)
}

func (ue *AmfUe) Remove() {
	ue.StopT3513()
	ue.StopT3565()
	ue.StopT3560()
	ue.StopT3550()
	ue.StopT3522()
	ue.StopT3570()
	ue.StopT3555()

	ue.RanUeMu.Lock()
	ranUes := make([]*RanUe, 0, len(ue.RanUe))
	for _, ranUe := range ue.RanUe {
		ranUes = append(ranUes, ranUe)
	}
	anTypeFlags := make(map[models.AccessType]bool, len(ue.AnTypeFlags))
	for accessType, flag := range ue.AnTypeFlags {
		anTypeFlags[accessType] = flag
	}
	ue.RanUeMu.Unlock()

	for _, ranUe := range ranUes {
		if err := ranUe.Remove(); err != nil {
			logger.CtxLog.Errorf("Remove RanUe error: %v", err)
		}
	}

	for accessType, flag := range anTypeFlags {
		if flag {
			business_metrics.DecrUeCmIdleStateGauge(accessType)
		}
	}
	tmsiGenerator.FreeID(int64(ue.Tmsi))
	if len(ue.Supi) > 0 {
		GetSelf().UePool.Delete(ue.Supi)
	}
	ue.DeleteAllSmContexts()

	logger.CtxLog.Infof("AmfUe[%s] is removed", ue.Supi)
}

// DetachRanUe detaches ranUe from the AmfUe.  A stale release (a RanUe that is
// no longer the one attached for anType) is ignored, so it cannot delete a
// newly attached RanUe of the same access type.
func (ue *AmfUe) DetachRanUe(anType models.AccessType, ranUe *RanUe) {
	if ue == nil {
		return
	}

	ue.RanUeMu.Lock()
	defer ue.RanUeMu.Unlock()
	ue.detachRanUe(anType, ranUe)
}

func (ue *AmfUe) detachRanUe(anType models.AccessType, ranUe *RanUe) {
	current, ok := ue.RanUe[anType]
	if !ok {
		// Another release already removed the entry; keep the metrics and the
		// log fields consistent with an empty slot.
		ue.updateLogFields(anType)
		return
	}
	if ranUe != nil && current != ranUe {
		// The release belongs to a RanUe that has already been replaced.
		return
	}

	// The link AmfUe <-/-> RanUe is broken, we update the cm-connected metrics gauges
	business_metrics.IncrUeCmIdleStateGauge(anType)
	business_metrics.DecrUeCmConnectedStateGauge(anType)
	// We want only to decrement the ue connectivity gauge if we remove the ran connection of the registered ue.
	if ue.State[anType] != nil && ue.State[anType].Is(Registered) {
		business_metrics.DecrUeConnectivityGauge(anType)
	}

	delete(ue.RanUe, anType)
	ue.updateLogFields(anType)
}

// AttachRanUe attaches ranUe to the AmfUe.  Use
// gmm_common.AttachRanUeToAmfUeAndReleaseOldIfAny() for the complete ownership
// transition; this method only takes the RanUeMu lock and updates the link.
func (ue *AmfUe) AttachRanUe(ranUe *RanUe) {
	ue.RanUeMu.Lock()
	defer ue.RanUeMu.Unlock()
	ue.AttachRanUeLocked(ranUe)
}

// AttachRanUeLocked updates the link.  The caller must hold ue.RanUeMu.
// ranUe.AmfUe is published last, so a goroutine that reaches the AmfUe
// through ranUe.GetAmfUe() also sees the log fields set here.
func (ue *AmfUe) AttachRanUeLocked(ranUe *RanUe) {
	ue.RanUe[ranUe.Ran.AnType] = ranUe
	ue.updateLogFields(ranUe.Ran.AnType)
	ranUe.SetAmfUe(ue)
}

// UpdateLogFields refreshes the per-UE logger fields.  It is serialized with
// the RanUe attach/detach transitions because it reads the current RanUe.
func (ue *AmfUe) UpdateLogFields(accessType models.AccessType) {
	ue.RanUeMu.Lock()
	defer ue.RanUeMu.Unlock()
	ue.updateLogFields(accessType)
}

// updateLogFields refreshes the per-UE logger fields.  The caller must hold
// ue.RanUeMu (read or write).
func (ue *AmfUe) updateLogFields(accessType models.AccessType) {
	anTypeStr := ""
	switch accessType {
	case models.AccessType_3_GPP_ACCESS:
		anTypeStr = "3GPP"
	case models.AccessType_NON_3_GPP_ACCESS:
		anTypeStr = "Non3GPP"
	}
	if ranUe, ok := ue.RanUe[accessType]; ok {
		ue.NASLog = ue.NASLog.WithField(logger.FieldAmfUeNgapID, fmt.Sprintf("RU:%d,AU:%d(%s)",
			ranUe.RanUeNgapId, ranUe.AmfUeNgapId, anTypeStr))
		ue.GmmLog = ue.GmmLog.WithField(logger.FieldAmfUeNgapID, fmt.Sprintf("RU:%d,AU:%d(%s)",
			ranUe.RanUeNgapId, ranUe.AmfUeNgapId, anTypeStr))
	} else {
		ue.NASLog = ue.NASLog.WithField(logger.FieldAmfUeNgapID, fmt.Sprintf("RU:,AU:(%s)", anTypeStr))
		ue.GmmLog = ue.GmmLog.WithField(logger.FieldAmfUeNgapID, fmt.Sprintf("RU:,AU:(%s)", anTypeStr))
	}

	// will log "[SUPI:]" if ue.SUPI==""
	ue.NASLog = ue.NASLog.WithField(logger.FieldSupi, fmt.Sprintf("SUPI:%s", ue.Supi))
	ue.GmmLog = ue.GmmLog.WithField(logger.FieldSupi, fmt.Sprintf("SUPI:%s", ue.Supi))
	ue.ProducerLog = ue.ProducerLog.WithField(logger.FieldSupi, fmt.Sprintf("SUPI:%s", ue.Supi))
}

func (ue *AmfUe) GetAnType() models.AccessType {
	if ue.CmConnect(models.AccessType_3_GPP_ACCESS) {
		return models.AccessType_3_GPP_ACCESS
	} else if ue.CmConnect(models.AccessType_NON_3_GPP_ACCESS) {
		return models.AccessType_NON_3_GPP_ACCESS
	}
	return ""
}

func (ue *AmfUe) GetCmInfo() (cmInfos []models.Amf_EvtExpos_CmInfo) {
	var cmInfo models.Amf_EvtExpos_CmInfo
	cmInfo.AccessType = models.AccessType_3_GPP_ACCESS
	if ue.CmConnect(cmInfo.AccessType) {
		cmInfo.CmState = models.Amf_EvtExpos_CmState_CONNECTED
	} else {
		cmInfo.CmState = models.Amf_EvtExpos_CmState_IDLE
	}
	cmInfos = append(cmInfos, cmInfo)
	cmInfo.AccessType = models.AccessType_NON_3_GPP_ACCESS
	if ue.CmConnect(cmInfo.AccessType) {
		cmInfo.CmState = models.Amf_EvtExpos_CmState_CONNECTED
	} else {
		cmInfo.CmState = models.Amf_EvtExpos_CmState_IDLE
	}
	cmInfos = append(cmInfos, cmInfo)
	return
}

func (ue *AmfUe) InAllowedNssai(targetSNssai models.Snssai, anType models.AccessType) bool {
	for _, allowedSnssai := range ue.AllowedNssai[anType] {
		if openapi.SnssaiEqualFold(*allowedSnssai.AllowedSnssai, targetSNssai) {
			return true
		}
	}
	return false
}

func (ue *AmfUe) InSubscribedNssai(targetSNssai models.Snssai) bool {
	for _, sNssai := range ue.SubscribedNssai {
		if openapi.SnssaiEqualFold(*sNssai.SubscribedSnssai, targetSNssai) {
			return true
		}
	}
	return false
}

func (ue *AmfUe) GetNsiInformationFromSnssai(
	anType models.AccessType,
	snssai models.Snssai,
) *models.Nssf_NSSel_NsiInformation {
	for _, allowedSnssai := range ue.AllowedNssai[anType] {
		if openapi.SnssaiEqualFold(*allowedSnssai.AllowedSnssai, snssai) {
			// TODO: select NsiInformation based on operator policy
			if len(allowedSnssai.NsiInformationList) != 0 {
				return &allowedSnssai.NsiInformationList[0]
			}
		}
	}
	return nil
}

func (ue *AmfUe) TaiListInRegistrationArea(taiList []models.Tai, accessType models.AccessType) bool {
	for _, tai := range taiList {
		if !InTaiList(tai, ue.RegistrationArea[accessType]) {
			return false
		}
	}
	return true
}

func (ue *AmfUe) HasWildCardSubscribedDNN() bool {
	for _, snssaiInfo := range ue.SmfSelectionData.SubscribedSnssaiInfos {
		for _, dnnInfo := range snssaiInfo.DnnInfos {
			if dnnInfo.Dnn == "*" {
				return true
			}
		}
	}
	return false
}

func (ue *AmfUe) SecurityContextIsValid() bool {
	return ue.SecurityContextAvailable && ue.NgKsi.Ksi != int32(ie.NASKeyNA) && !ue.MacFailed
}

// Kamf Derivation function defined in TS 33.501 Annex A.7
func (ue *AmfUe) DerivateKamf() {
	supiRegexp, err := regexp.Compile("(?:imsi|supi)-([0-9]{5,15})")
	if err != nil {
		logger.CtxLog.Error(err)
		return
	}
	groups := supiRegexp.FindStringSubmatch(ue.Supi)
	if groups == nil {
		logger.NasLog.Errorln("supi is not correct")
		return
	}

	P0 := []byte(groups[1])
	L0 := ueauth.KDFLen(P0)
	P1 := ue.ABBA
	L1 := ueauth.KDFLen(P1)

	KseafDecode, err := hex.DecodeString(ue.Kseaf)
	if err != nil {
		logger.CtxLog.Error(err)
		return
	}
	KamfBytes, err := ueauth.GetKDFValue(KseafDecode, ueauth.FC_FOR_KAMF_DERIVATION, P0, L0, P1, L1)
	if err != nil {
		logger.CtxLog.Error(err)
		return
	}
	ue.Kamf = hex.EncodeToString(KamfBytes)
}

// Algorithm key Derivation function defined in TS 33.501 Annex A.9
func (ue *AmfUe) DerivateAlgKey() {
	// Security Key
	P0 := []byte{message.NNASEncAlg}
	L0 := ueauth.KDFLen(P0)
	P1 := []byte{ue.CipheringAlg}
	L1 := ueauth.KDFLen(P1)

	KamfBytes, err := hex.DecodeString(ue.Kamf)
	if err != nil {
		logger.CtxLog.Error(err)
		return
	}
	kenc, err := ueauth.GetKDFValue(KamfBytes, ueauth.FC_FOR_ALGORITHM_KEY_DERIVATION, P0, L0, P1, L1)
	if err != nil {
		logger.CtxLog.Error(err)
		return
	}
	copy(ue.KnasEnc[:], kenc[16:32])

	// Integrity Key
	P0 = []byte{message.NNASIntAlg}
	L0 = ueauth.KDFLen(P0)
	P1 = []byte{ue.IntegrityAlg}
	L1 = ueauth.KDFLen(P1)

	kint, err := ueauth.GetKDFValue(KamfBytes, ueauth.FC_FOR_ALGORITHM_KEY_DERIVATION, P0, L0, P1, L1)
	if err != nil {
		logger.CtxLog.Error(err)
		return
	}
	copy(ue.KnasInt[:], kint[16:32])
}

// Access Network key Derivation function defined in TS 33.501 Annex A.9
func (ue *AmfUe) DerivateAnKey(anType models.AccessType) {
	accessType := message.AccessType3GPP // Defalut 3gpp
	P0 := make([]byte, 4)
	binary.BigEndian.PutUint32(P0, ue.ULCount.Get())
	L0 := ueauth.KDFLen(P0)
	if anType == models.AccessType_NON_3_GPP_ACCESS {
		accessType = message.AccessTypeNon3GPP
	}
	P1 := []byte{byte(accessType)}
	L1 := ueauth.KDFLen(P1)

	KamfBytes, err := hex.DecodeString(ue.Kamf)
	if err != nil {
		logger.CtxLog.Error(err)
		return
	}
	key, err := ueauth.GetKDFValue(KamfBytes, ueauth.FC_FOR_KGNB_KN3IWF_DERIVATION, P0, L0, P1, L1)
	if err != nil {
		logger.CtxLog.Error(err)
		return
	}
	switch accessType {
	case message.AccessType3GPP:
		ue.Kgnb = key
	case message.AccessTypeNon3GPP:
		ue.Kn3iwf = key
	}
}

// NH Derivation function defined in TS 33.501 Annex A.10
func (ue *AmfUe) DerivateNH(syncInput []byte) {
	P0 := syncInput
	L0 := ueauth.KDFLen(P0)

	KamfBytes, err := hex.DecodeString(ue.Kamf)
	if err != nil {
		logger.CtxLog.Error(err)
		return
	}
	ue.NH, err = ueauth.GetKDFValue(KamfBytes, ueauth.FC_FOR_NH_DERIVATION, P0, L0)
	if err != nil {
		logger.CtxLog.Error(err)
		return
	}
}

func (ue *AmfUe) UpdateSecurityContext(anType models.AccessType) {
	ue.DerivateAnKey(anType)
	switch anType {
	case models.AccessType_3_GPP_ACCESS:
		ue.DerivateNH(ue.Kgnb)
	case models.AccessType_NON_3_GPP_ACCESS:
		ue.DerivateNH(ue.Kn3iwf)
	}
	ue.NCC = 1
}

func (ue *AmfUe) UpdateNH() {
	ue.NCC++
	// TS33.501 6.2.3.2 Key identification
	// The next hop chaining count, NCC, represents the 3 least significant bits of this counter.
	ue.NCC &= 0x7

	ue.DerivateNH(ue.NH)
}

func (ue *AmfUe) SelectSecurityAlg(intOrder, encOrder []uint8) error {
	ue.CipheringAlg = uint8(message.AlgCiphering128NEA0)
	ue.IntegrityAlg = uint8(message.AlgIntegrity128NIA0)

	ueSupported := uint8(0)
	for _, intAlg := range intOrder {
		switch intAlg {
		case uint8(message.AlgIntegrity128NIA0):
			// TODO: Revisit this if AMF adds explicit emergency registration support.
			continue
		case uint8(message.AlgIntegrity128NIA1):
			if ue.UESecurityCapability.IA1_128_5G {
				ueSupported = 1
			}
		case uint8(message.AlgIntegrity128NIA2):
			if ue.UESecurityCapability.IA2_128_5G {
				ueSupported = 1
			}
		case uint8(message.AlgIntegrity128NIA3):
			if ue.UESecurityCapability.IA3_128_5G {
				ueSupported = 1
			}
		}
		if ueSupported == 1 {
			ue.IntegrityAlg = intAlg
			break
		}
	}
	if ueSupported != 1 {
		return errors.New("no matched integrity algorithm")
	}

	ueSupported = uint8(0)
	for _, encAlg := range encOrder {
		switch encAlg {
		case uint8(message.AlgCiphering128NEA0):
			if ue.UESecurityCapability.EA05G {
				ueSupported = 1
			}
		case uint8(message.AlgCiphering128NEA1):
			if ue.UESecurityCapability.EA1_128_5G {
				ueSupported = 1
			}
		case uint8(message.AlgCiphering128NEA2):
			if ue.UESecurityCapability.EA2_128_5G {
				ueSupported = 1
			}
		case uint8(message.AlgCiphering128NEA3):
			if ue.UESecurityCapability.EA3_128_5G {
				ueSupported = 1
			}
		}
		if ueSupported == 1 {
			ue.CipheringAlg = encAlg
			break
		}
	}
	if ueSupported != 1 {
		return errors.New("no matched encrypt algorithm")
	}

	return nil
}

func (ue *AmfUe) ClearRegistrationRequestData(accessType models.AccessType) {
	ue.RegistrationRequest = nil
	ue.RegistrationType5GS = 0
	ue.IdentityTypeUsedForRegistration = 0
	ue.AuthFailureCauseSynchFailureTimes = 0
	ue.IdentityRequestSendTimes = 0
	ue.ServingAmfChanged = false
	ue.RegistrationAcceptForNon3GPPAccess = nil
	if ranUe := ue.GetRanUe(accessType); ranUe != nil {
		ranUe.UeContextRequest = factory.AmfConfig.Configuration.DefaultUECtxReq
	}
	ue.RetransmissionOfInitialNASMsg = false
	ue.onGoingMu.Lock()
	if onGoing := ue.onGoing[accessType]; onGoing != nil {
		onGoing.Procedure = OnGoingProcedureNothing
	}
	ue.onGoingMu.Unlock()
}

func (ue *AmfUe) SetOnGoing(anType models.AccessType, onGoing *OnGoing) {
	ue.onGoingMu.Lock()
	prevOnGoing := ue.onGoing[anType]
	ue.onGoing[anType] = onGoing
	var prevProcedure, procedure OnGoingProcedure
	var prevPpi, ppi int32
	if prevOnGoing != nil {
		prevProcedure, prevPpi = prevOnGoing.Procedure, prevOnGoing.Ppi
	}
	if onGoing != nil {
		procedure, ppi = onGoing.Procedure, onGoing.Ppi
	}
	ue.onGoingMu.Unlock()

	ue.GmmLog.Debugf("OnGoing[%s]->[%s] PPI[%d]->[%d]", prevProcedure, procedure, prevPpi, ppi)
}

// OnGoing returns a copy of the procedure in progress for anType.
func (ue *AmfUe) OnGoing(anType models.AccessType) OnGoing {
	ue.onGoingMu.RLock()
	defer ue.onGoingMu.RUnlock()
	if onGoing := ue.onGoing[anType]; onGoing != nil {
		return *onGoing
	}
	return OnGoing{Procedure: OnGoingProcedureNothing}
}

func (ue *AmfUe) RemoveAmPolicyAssociation() {
	ue.AmPolicyAssociation = nil
	ue.PolicyAssociationId = ""
}

func (ue *AmfUe) CopyDataFromUeContextModel(ueContext *models.Amf_Comm_UeContext) {
	if ueContext.Supi != "" {
		ue.Supi = ueContext.Supi
		ue.UnauthenticatedSupi = ueContext.SupiUnauthInd
	}

	if ueContext.Pei != "" {
		ue.Pei = ueContext.Pei
	}

	if ueContext.UdmGroupId != "" {
		ue.UdmGroupId = ueContext.UdmGroupId
	}

	if ueContext.AusfGroupId != "" {
		ue.AusfGroupId = ueContext.AusfGroupId
	}

	if ueContext.RoutingIndicator != "" {
		ue.RoutingIndicator = ueContext.RoutingIndicator
	}

	if ueContext.SubUeAmbr != nil {
		if ue.AccessAndMobilitySubscriptionData == nil {
			ue.AccessAndMobilitySubscriptionData = new(models.Udm_SDM_AccessAndMobilitySubscriptionData)
		}
		if ue.AccessAndMobilitySubscriptionData.SubscribedUeAmbr == nil {
			ue.AccessAndMobilitySubscriptionData.SubscribedUeAmbr = new(models.AmbrRm)
		}

		subAmbr := ue.AccessAndMobilitySubscriptionData.SubscribedUeAmbr
		subAmbr.Uplink = ueContext.SubUeAmbr.Uplink
		subAmbr.Downlink = ueContext.SubUeAmbr.Downlink
	}

	if ueContext.SubRfsp != 0 {
		if ue.AccessAndMobilitySubscriptionData == nil {
			ue.AccessAndMobilitySubscriptionData = new(models.Udm_SDM_AccessAndMobilitySubscriptionData)
		}
		ue.AccessAndMobilitySubscriptionData.RfspIndex = ueContext.SubRfsp
	}

	if len(ueContext.RestrictedRatList) > 0 {
		if ue.AccessAndMobilitySubscriptionData == nil {
			ue.AccessAndMobilitySubscriptionData = new(models.Udm_SDM_AccessAndMobilitySubscriptionData)
		}
		ue.AccessAndMobilitySubscriptionData.RatRestrictions = ueContext.RestrictedRatList
	}

	if len(ueContext.ForbiddenAreaList) > 0 {
		if ue.AccessAndMobilitySubscriptionData == nil {
			ue.AccessAndMobilitySubscriptionData = new(models.Udm_SDM_AccessAndMobilitySubscriptionData)
		}
		ue.AccessAndMobilitySubscriptionData.ForbiddenAreas = ueContext.ForbiddenAreaList
	}

	if ueContext.ServiceAreaRestriction != nil {
		if ue.AccessAndMobilitySubscriptionData == nil {
			ue.AccessAndMobilitySubscriptionData = new(models.Udm_SDM_AccessAndMobilitySubscriptionData)
		}
		ue.AccessAndMobilitySubscriptionData.ServiceAreaRestriction = ueContext.ServiceAreaRestriction
	}

	if ueContext.SeafData != nil {
		seafData := ueContext.SeafData

		ue.NgKsi = *seafData.NgKsi
		if seafData.KeyAmf != nil {
			if seafData.KeyAmf.KeyType == models.Amf_Comm_KeyAmfType_KAMF {
				ue.Kamf = seafData.KeyAmf.KeyVal
			}
		}
		if nh, err := hex.DecodeString(seafData.Nh); err != nil {
			logger.CtxLog.Error(err)
			return
		} else {
			ue.NH = nh
		}
		ue.NCC = uint8(seafData.Ncc)
	} else {
		ue.SecurityContextAvailable = false
	}

	if ueContext.PcfId != "" {
		ue.PcfId = ueContext.PcfId
	}

	if ueContext.PcfAmPolicyUri != "" {
		ue.AmPolicyUri = ueContext.PcfAmPolicyUri
	}

	if len(ueContext.AmPolicyReqTriggerList) > 0 {
		if ue.AmPolicyAssociation == nil {
			ue.AmPolicyAssociation = new(models.Pcf_AMPolCtrl_PolicyAssociation)
		}
		for _, trigger := range ueContext.AmPolicyReqTriggerList {
			switch trigger {
			case models.Amf_Comm_PolicyReqTrigger_LOCATION_CHANGE:
				ue.AmPolicyAssociation.Triggers = append(ue.AmPolicyAssociation.Triggers,
					models.Pcf_AMPolCtrl_RequestTrigger_LOC_CH)
			case models.Amf_Comm_PolicyReqTrigger_PRA_CHANGE:
				ue.AmPolicyAssociation.Triggers = append(ue.AmPolicyAssociation.Triggers,
					models.Pcf_AMPolCtrl_RequestTrigger_PRA_CH)
			case models.Amf_Comm_PolicyReqTrigger_ALLOWED_NSSAI_CHANGE:
				ue.AmPolicyAssociation.Triggers = append(ue.AmPolicyAssociation.Triggers,
					models.Pcf_AMPolCtrl_RequestTrigger_ALLOWED_NSSAI_CH)
			case models.Amf_Comm_PolicyReqTrigger_NWDAF_DATA_CHANGE:
				ue.AmPolicyAssociation.Triggers = append(ue.AmPolicyAssociation.Triggers,
					models.Pcf_AMPolCtrl_RequestTrigger_NWDAF_DATA_CH)
			case models.Amf_Comm_PolicyReqTrigger_SMF_SELECT_CHANGE:
				ue.AmPolicyAssociation.Triggers = append(ue.AmPolicyAssociation.Triggers,
					models.Pcf_AMPolCtrl_RequestTrigger_SMF_SELECT_CH)
			case models.Amf_Comm_PolicyReqTrigger_ACCESS_TYPE_CHANGE:
				ue.AmPolicyAssociation.Triggers = append(ue.AmPolicyAssociation.Triggers,
					models.Pcf_AMPolCtrl_RequestTrigger_ACCESS_TYPE_CH)
			}
		}
	}

	if len(ueContext.SessionContextList) > 0 {
		for index := range ueContext.SessionContextList {
			smContext := SmContext{
				pduSessionID: ueContext.SessionContextList[index].PduSessionId,
				smContextRef: ueContext.SessionContextList[index].SmContextRef,
				snssai:       *ueContext.SessionContextList[index].SNssai,
				dnn:          ueContext.SessionContextList[index].Dnn,
				accessType:   ueContext.SessionContextList[index].AccessType,
				hSmfID:       ueContext.SessionContextList[index].HsmfId,
				vSmfID:       ueContext.SessionContextList[index].VsmfId,
				nsInstance:   ueContext.SessionContextList[index].NsInstance,
			}
			ue.StoreSmContext(ueContext.SessionContextList[index].PduSessionId, &smContext)
		}
	}

	if len(ueContext.MmContextList) > 0 {
		for _, mmContext := range ueContext.MmContextList {
			if mmContext.AccessType == models.AccessType_3_GPP_ACCESS {
				if nasSecurityMode := mmContext.NasSecurityMode; nasSecurityMode != nil {
					switch nasSecurityMode.IntegrityAlgorithm {
					case models.Amf_Comm_IntegrityAlgorithm_NIA0:
						ue.IntegrityAlg = uint8(message.AlgIntegrity128NIA0)
					case models.Amf_Comm_IntegrityAlgorithm_NIA1:
						ue.IntegrityAlg = uint8(message.AlgIntegrity128NIA1)
					case models.Amf_Comm_IntegrityAlgorithm_NIA2:
						ue.IntegrityAlg = uint8(message.AlgIntegrity128NIA2)
					case models.Amf_Comm_IntegrityAlgorithm_NIA3:
						ue.IntegrityAlg = uint8(message.AlgIntegrity128NIA3)
					}

					switch nasSecurityMode.CipheringAlgorithm {
					case models.Amf_Comm_CipheringAlgorithm_NEA0:
						ue.CipheringAlg = uint8(message.AlgCiphering128NEA0)
					case models.Amf_Comm_CipheringAlgorithm_NEA1:
						ue.CipheringAlg = uint8(message.AlgCiphering128NEA1)
					case models.Amf_Comm_CipheringAlgorithm_NEA2:
						ue.CipheringAlg = uint8(message.AlgCiphering128NEA2)
					case models.Amf_Comm_CipheringAlgorithm_NEA3:
						ue.CipheringAlg = uint8(message.AlgCiphering128NEA3)
					}

					if mmContext.NasDownlinkCount != 0 {
						overflow := uint16((uint32(mmContext.NasDownlinkCount) & 0x00ffff00) >> 8)
						sqn := uint8(uint32(mmContext.NasDownlinkCount & 0x000000ff))
						ue.DLCount.Set(overflow, sqn)
					}

					if mmContext.NasUplinkCount != 0 {
						overflow := uint16((uint32(mmContext.NasUplinkCount) & 0x00ffff00) >> 8)
						sqn := uint8(uint32(mmContext.NasUplinkCount & 0x000000ff))
						ue.ULCount.Set(overflow, sqn)
					}

					// TS 29.518 Table 6.1.6.3.2.1
					if mmContext.UeSecurityCapability != "" {
						// ue.SecurityCapabilities
						buf, err := base64.StdEncoding.DecodeString(mmContext.UeSecurityCapability)
						if err != nil {
							logger.CtxLog.Error(err)
							return
						}
						if err = ue.UESecurityCapability.UnmarshalBinary(buf); err != nil {
							logger.CtxLog.Error(err)
							return
						}
					}
				}
			}

			if mmContext.AllowedNssai != nil {
				for _, snssai := range mmContext.AllowedNssai {
					allowedSnssai := models.Nssf_NSSel_AllowedSnssai{
						AllowedSnssai: &snssai,
					}
					ue.AllowedNssai[mmContext.AccessType] = append(ue.AllowedNssai[mmContext.AccessType], allowedSnssai)
				}
			}
		}
	}
	if ueContext.TraceData != nil {
		ue.TraceData = ueContext.TraceData
	}
}

// SM Context realted function
func (ue *AmfUe) StoreSmContext(pduSessionID int32, smContext *SmContext) {
	if smContext != nil {
		business_metrics.IncrPduSessionEventCounter(string(smContext.accessType), business_metrics.PDU_SESSION_CREATION_EVENT)
	}
	ue.SmContextList.Store(pduSessionID, smContext)
}

func (ue *AmfUe) DeleteSmContext(pduSessionID int32, anType models.AccessType) {
	business_metrics.IncrPduSessionEventCounter(string(anType), business_metrics.PDU_SESSION_RELEASE_EVENT)
	ue.SmContextList.Delete(pduSessionID)
}

func (ue *AmfUe) DeleteAllSmContexts() {
	ue.SmContextList.Range(func(key, value interface{}) bool {
		pduId, ok := key.(int32)
		if !ok {
			return true
		}
		smCtx, ok := value.(*SmContext)
		if !ok {
			return true
		}
		ue.DeleteSmContext(pduId, smCtx.AccessType())
		return true
	})
}

func (ue *AmfUe) SmContextFindByPDUSessionID(pduSessionID int32) (*SmContext, bool) {
	if value, ok := ue.SmContextList.Load(pduSessionID); ok {
		return value.(*SmContext), true
	}
	return nil, false
}

func (ue *AmfUe) UpdateBackupAmfInfo(backupAmfInfo models.BackupAmfInfo) {
	isExist := false
	for _, amfInfo := range ue.BackupAmfInfo {
		if amfInfo.BackupAmf == backupAmfInfo.BackupAmf {
			isExist = true
			break
		}
	}
	if !isExist {
		ue.BackupAmfInfo = append(ue.BackupAmfInfo, backupAmfInfo)
	}
}

func (ue *AmfUe) StopT3513() {
	timer := ue.takeTimer(&ue.T3513)
	if timer == nil {
		return
	}

	ue.GmmLog.Infof("Stop T3513 timer")
	timer.Stop()
}

func (ue *AmfUe) StopT3565() {
	timer := ue.takeTimer(&ue.T3565)
	if timer == nil {
		return
	}

	ue.GmmLog.Infof("Stop T3565 timer")
	timer.Stop()
}

func (ue *AmfUe) StopT3560() {
	timer := ue.takeTimer(&ue.T3560)
	if timer == nil {
		return
	}

	ue.GmmLog.Infof("Stop T3560 timer")
	timer.Stop()
}

// StopT3550 stops T3550 and reports whether it was running.  When it returns
// true, T3550's last expiry cannot run its abort callback any more.
func (ue *AmfUe) StopT3550() bool {
	timer := ue.takeTimer(&ue.T3550)
	if timer == nil {
		return false
	}

	ue.GmmLog.Infof("Stop T3550 timer")
	timer.Stop()
	return true
}

func (ue *AmfUe) StopT3522() {
	timer := ue.takeTimer(&ue.T3522)
	if timer == nil {
		return
	}

	ue.GmmLog.Infof("Stop T3522 timer")
	timer.Stop()
}

func (ue *AmfUe) StopT3570() {
	timer := ue.takeTimer(&ue.T3570)
	if timer == nil {
		return
	}

	ue.GmmLog.Infof("Stop T3570 timer")
	timer.Stop()
}

func (ue *AmfUe) StopT3555() {
	timer := ue.takeTimer(&ue.T3555)
	if timer == nil {
		return
	}

	ue.GmmLog.Infof("Stop T3555 timer")
	timer.Stop()
}

func (ue *AmfUe) CheckSliceAvailabilityInCurrentRan(targetSnssai models.Snssai, anType models.AccessType) bool {
	ranUe := ue.GetRanUe(anType)
	if ranUe == nil || ranUe.Ran == nil {
		ue.GmmLog.Warn("CheckSliceAvailabilityInCurrentRan: RanUe or Ran is nil")
		return false
	}

	return ue.CheckSliceAvailabilityInRan(targetSnssai, ranUe.Ran, ue.Tai)
}

func (ue *AmfUe) CheckSliceAvailabilityInTargetRan(
	targetSnssai models.Snssai,
	targetRan *AmfRan,
	targetTai models.Tai,
) bool {
	return ue.CheckSliceAvailabilityInRan(targetSnssai, targetRan, targetTai)
}

func (ue *AmfUe) CheckSliceAvailabilityInRan(targetSnssai models.Snssai, ran *AmfRan, targetTai models.Tai) bool {
	if ran == nil {
		ue.GmmLog.Warn("CheckSliceAvailabilityInRan: Ran is nil")
		return false
	}

	for _, taiItem := range ran.SupportedTAList {
		if taiItem.Tai.Tac == targetTai.Tac &&
			taiItem.Tai.PlmnId.Mcc == targetTai.PlmnId.Mcc &&
			taiItem.Tai.PlmnId.Mnc == targetTai.PlmnId.Mnc {
			for _, supportedSnssai := range taiItem.SNssaiList {
				if snssaiSupported(targetSnssai, supportedSnssai) {
					return true
				}
			}
		}
	}
	return false
}

func (ue *AmfUe) CheckSliceAvailabilityInRegistrationArea(targetSnssai models.Snssai, anType models.AccessType) bool {
	// if ue is in CONNECTED state, directly check the current RAN
	if ue.CmConnect(anType) {
		return ue.CheckSliceAvailabilityInCurrentRan(targetSnssai, anType)
	}
	// if ue is in IDLE state, need to check all TAIs in Registration Area
	// according to TS 23.502 4.2.3.3 Step 3b:
	// if any TAI in the Registration Area supports the requested S-NSSAI, paging is allowed
	RegistrationAreaMap := make(map[string]bool)

	for _, tai := range ue.RegistrationArea[anType] {
		key := tai.PlmnId.Mcc + tai.PlmnId.Mnc + tai.Tac
		RegistrationAreaMap[key] = true
	}
	supported := false
	ue.ServingAMF().AmfRanPool.Range(func(key, value interface{}) bool {
		ran := value.(*AmfRan)
		for _, supportedItem := range ran.SupportedTAList {
			taiKey := supportedItem.Tai.PlmnId.Mcc + supportedItem.Tai.PlmnId.Mnc + supportedItem.Tai.Tac
			if _, exists := RegistrationAreaMap[taiKey]; exists {
				for _, supportedSnssai := range supportedItem.SNssaiList {
					if snssaiSupported(targetSnssai, supportedSnssai) {
						supported = true
						return false
					}
				}
			}
		}
		return true
	})
	return supported
}
