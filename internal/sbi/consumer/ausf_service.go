package consumer

import (
	"encoding/base64"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"sync"

	amf_context "github.com/free5gc/amf/internal/context"
	"github.com/free5gc/nas/ie"
	"github.com/free5gc/openapi"
	Nausf_UEAuthentication "github.com/free5gc/openapi/ausf/UEAU"
	"github.com/free5gc/openapi/models"
	sbi_metrics "github.com/free5gc/util/metrics/sbi"
)

type nausfService struct {
	consumer *Consumer

	UEAuthenticationMu sync.RWMutex

	UEAuthenticationClients map[string]*Nausf_UEAuthentication.APIClient
}

func (s *nausfService) getUEAuthenticationClient(uri string) *Nausf_UEAuthentication.APIClient {
	if uri == "" {
		return nil
	}
	s.UEAuthenticationMu.RLock()
	client, ok := s.UEAuthenticationClients[uri]
	if ok {
		s.UEAuthenticationMu.RUnlock()
		return client
	}

	configuration := Nausf_UEAuthentication.NewConfiguration()
	configuration.SetBasePath(uri)
	configuration.SetMetrics(sbi_metrics.SbiMetricHook)
	client = Nausf_UEAuthentication.NewAPIClient(configuration)

	s.UEAuthenticationMu.RUnlock()
	s.UEAuthenticationMu.Lock()
	defer s.UEAuthenticationMu.Unlock()
	s.UEAuthenticationClients[uri] = client
	return client
}

func (s *nausfService) SendUEAuthenticationAuthenticateRequest(ue *amf_context.AmfUe,
	resynchronizationInfo *models.Udm_UEAU_ResynchronizationInfo,
) (*models.Ausf_UEAU_UEAuthenticationCtx, *models.ProblemDetails, error) {
	client := s.getUEAuthenticationClient(ue.AusfUri)
	if client == nil {
		return nil, nil, openapi.ReportError("ausf not found")
	}

	amfSelf := amf_context.GetSelf()
	servedGuami := amfSelf.ServedGuamiList[0]

	var authInfo models.Ausf_UEAU_AuthenticationInfo
	authInfo.SupiOrSuci = ue.Suci
	if mnc, err := strconv.Atoi(servedGuami.PlmnId.Mnc); err != nil {
		return nil, nil, err
	} else {
		authInfo.ServingNetworkName = fmt.Sprintf("5G:mnc%03d.mcc%s.3gppnetwork.org", mnc, servedGuami.PlmnId.Mcc)
	}
	if resynchronizationInfo != nil {
		authInfo.ResynchronizationInfo = resynchronizationInfo
	}
	ctx, _, err := amf_context.GetSelf().GetTokenCtxForNFInstance(
		models.Nrf_NFMgmt_ServiceName_NAUSF_AUTH, models.Nrf_NFMgmt_NFType_AUSF, ue.AusfId)
	if err != nil {
		return nil, nil, err
	}

	authReq := Nausf_UEAuthentication.UeAuthenticationsPostRequest{
		RequestBody: &authInfo,
	}

	res, localErr := client.DefaultApi.UeAuthenticationsPost(ctx, &authReq)
	if localErr == nil {
		return res.Ausf_UEAU_UEAuthenticationCtx, nil, nil
	} else {
		switch errType := localErr.(type) {
		// API error
		case openapi.GenericOpenAPIError:
			switch errModel := errType.Model().(type) {
			case Nausf_UEAuthentication.UeAuthenticationsPostError:
				return nil, errModel.ProblemDetails, localErr
			case error:
				return nil, openapi.ProblemDetailsSystemFailure(errModel.Error()), nil
			default:
				return nil, nil, openapi.ReportError("openapi error")
			}
		case error:
			return nil, openapi.ProblemDetailsSystemFailure(errType.Error()), err
		default:
			return nil, nil, openapi.ReportError("server no response")
		}
	}
}

func (s *nausfService) SendAuth5gAkaConfirmRequest(ue *amf_context.AmfUe, resStar string) (
	*models.Ausf_UEAU_ConfirmationDataResponse, *models.ProblemDetails, error,
) {
	confirmUri, ausfUri, err := resolveAUSFConfirmationURI(ue, "5g-aka")
	if err != nil {
		return nil, nil, err
	}

	client := s.getUEAuthenticationClient(ausfUri)
	if client == nil {
		return nil, nil, openapi.ReportError("ausf not found")
	}

	ctx, _, err := amf_context.GetSelf().GetTokenCtxForNFInstance(
		models.Nrf_NFMgmt_ServiceName_NAUSF_AUTH, models.Nrf_NFMgmt_NFType_AUSF, ue.AusfId)
	if err != nil {
		return nil, nil, err
	}
	// confirmUri.RequestURI() = "/nausf-auth/v1/ue-authentications/{authctxId}/5g-aka-confirmation"
	// splituri = ["","nausf-auth","v1","ue-authentications",{authctxId},"5g-aka-confirmation"]
	// authctxId = {authctxId}
	splituri := strings.Split(confirmUri.RequestURI(), "/")
	authctxId := ""
	if len(splituri) > 4 {
		authctxId = splituri[4]
	} else {
		return nil, nil, fmt.Errorf("authctxId is nil")
	}

	confirmData := &Nausf_UEAuthentication.UeAuthenticationsAuthCtxId5gAkaConfirmationPutRequest{
		AuthCtxId: &authctxId,
		RequestBody: &models.Ausf_UEAU_ConfirmationData{
			ResStar: &resStar,
		},
	}
	confirmResult, localErr := client.DefaultApi.UeAuthenticationsAuthCtxId5gAkaConfirmationPut(
		ctx, confirmData)
	if localErr == nil {
		return confirmResult.Ausf_UEAU_ConfirmationDataResponse, nil, nil
	} else {
		switch err := localErr.(type) {
		// API error
		case openapi.GenericOpenAPIError:
			switch errModel := err.Model().(type) {
			case Nausf_UEAuthentication.UeAuthenticationsAuthCtxId5gAkaConfirmationPutError:
				return nil, errModel.ProblemDetails, localErr
			case error:
				return nil, openapi.ProblemDetailsSystemFailure(errModel.Error()), nil
			default:
				return nil, nil, openapi.ReportError("openapi error")
			}
		case error:
			return nil, openapi.ProblemDetailsSystemFailure(err.Error()), nil
		default:
			return nil, nil, openapi.ReportError("server no response")
		}
	}
}

func (s *nausfService) SendEapAuthConfirmRequest(ue *amf_context.AmfUe, eapMsg ie.EAPMsg) (
	response *models.Ausf_UEAU_EapSession, problemDetails *models.ProblemDetails, err1 error,
) {
	confirmUri, ausfUri, err := resolveAUSFConfirmationURI(ue, "eap-session")
	if err != nil {
		return nil, nil, err
	}

	client := s.getUEAuthenticationClient(ausfUri)
	if client == nil {
		return nil, nil, openapi.ReportError("ausf not found")
	}

	// confirmUri.RequestURI() = "/nausf-auth/v1/ue-authentications/{authctxId}/eap-session"
	// splituri = ["","nausf-auth","v1","ue-authentications",{authctxId},"eap-session"]
	// authctxId = {authctxId}
	splituri := strings.Split(confirmUri.RequestURI(), "/")
	authctxId := ""
	if len(splituri) > 4 {
		authctxId = splituri[4]
	} else {
		return nil, nil, fmt.Errorf("authctxId is nil")
	}

	eapSessionReq := Nausf_UEAuthentication.EapAuthMethodRequest{
		AuthCtxId: &authctxId,
		RequestBody: &models.Ausf_UEAU_EapSession{
			EapPayload: base64.StdEncoding.EncodeToString(eapMsg.Eap),
		},
	}
	ctx, _, err := amf_context.GetSelf().GetTokenCtxForNFInstance(
		models.Nrf_NFMgmt_ServiceName_NAUSF_AUTH, models.Nrf_NFMgmt_NFType_AUSF, ue.AusfId)
	if err != nil {
		return nil, nil, err
	}

	eapSession, localErr := client.DefaultApi.EapAuthMethod(ctx, &eapSessionReq)

	if localErr == nil {
		response = eapSession.Ausf_UEAU_EapSession
	} else {
		err = localErr
		switch errType := localErr.(type) {
		// API error
		case openapi.GenericOpenAPIError:
			switch errModel := errType.Model().(type) {
			case Nausf_UEAuthentication.EapAuthMethodError:
				problemDetails = errModel.ProblemDetails
			case error:
				problemDetails = openapi.ProblemDetailsSystemFailure(errModel.Error())
			default:
				err = openapi.ReportError("openapi error")
			}
		case error:
			problemDetails = openapi.ProblemDetailsSystemFailure(errType.Error())
		default:
			err = openapi.ReportError("server no response")
		}
	}

	return response, problemDetails, err
}

func resolveAUSFConfirmationURI(ue *amf_context.AmfUe, linkName string) (*url.URL, string, error) {
	if ue == nil {
		return nil, "", fmt.Errorf("AmfUe is nil")
	}
	if ue.AuthenticationCtx == nil {
		return nil, "", fmt.Errorf("ue authentication context is nil")
	}

	links := ue.AuthenticationCtx.Links[linkName]
	if len(links) == 0 || strings.TrimSpace(links[0].Href) == "" {
		return nil, "", fmt.Errorf("ausf confirmation link[%s] is empty", linkName)
	}

	confirmUri, err := url.Parse(links[0].Href)
	if err != nil {
		return nil, "", err
	}
	if validateErr := validateAUSFConfirmationURI(confirmUri); validateErr != nil {
		return nil, "", validateErr
	}

	ausfUri, err := url.Parse(ue.AusfUri)
	if err != nil {
		return nil, "", err
	}
	if validateErr := validateAUSFConfirmationURI(ausfUri); validateErr != nil {
		return nil, "", fmt.Errorf("invalid selected AUSF URI: %w", validateErr)
	}

	// TODO: If AMF stores all registered endpoints for the selected AUSF
	// instance, validate against that trusted endpoint set instead.
	if !strings.EqualFold(confirmUri.Scheme, ausfUri.Scheme) || !strings.EqualFold(confirmUri.Host, ausfUri.Host) {
		return nil, "", fmt.Errorf("ausf confirmation link[%s] authority %q does not match selected AUSF %q",
			linkName, confirmUri.Scheme+"://"+confirmUri.Host, ausfUri.Scheme+"://"+ausfUri.Host)
	}

	return confirmUri, strings.TrimRight(ue.AusfUri, "/"), nil
}

func validateAUSFConfirmationURI(uri *url.URL) error {
	if uri == nil {
		return fmt.Errorf("uri is nil")
	}

	switch strings.ToLower(uri.Scheme) {
	case "http", "https":
	default:
		return fmt.Errorf("invalid ausf confirmation uri scheme %q", uri.Scheme)
	}
	if uri.Host == "" {
		return fmt.Errorf("ausf confirmation uri host is empty")
	}

	return nil
}
