package consumer

import (
	"context"

	amf_context "github.com/free5gc/amf/internal/context"
	"github.com/free5gc/amf/internal/logger"
	"github.com/free5gc/openapi"
	"github.com/free5gc/openapi/models"
	"github.com/free5gc/openapi/oauth"
)

func GetTokenCtx(scope, targetNF string) (context.Context, *models.ProblemDetails, error) {
	if amf_context.GetSelf().OAuth2Required {
		logger.ConsumerLog.Debugln("GetToekenCtx")
		udrSelf := amf_context.GetSelf()
		tok, pd, err := oauth.SendAccTokenReq(udrSelf.NfId, models.NfType_AMF, scope, targetNF, udrSelf.NrfUri)
		if err != nil {
			return nil, pd, err
		}
		return context.WithValue(context.Background(),
			openapi.ContextOAuth2, tok), pd, nil
	}
	return context.TODO(), nil, nil
}
