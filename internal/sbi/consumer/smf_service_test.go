package consumer

import (
	"errors"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/free5gc/openapi"
	"github.com/free5gc/openapi/mediatype/multipart"
	"github.com/free5gc/openapi/models"
	Nsmf_PDUSession "github.com/free5gc/openapi/smf/PDUSess"
)

// A PDU SESSION ESTABLISHMENT REJECT for session 5, PTI 1, cause #28 "unknown PDU session type".
var testPduSessionEstablishmentReject = []byte{0x2e, 0x05, 0x01, 0xc3, 0x1c}

func testSmContextCreateError() *models.Smf_PDUSess_SmContextCreateError {
	return &models.Smf_PDUSess_SmContextCreateError{
		Error:   &models.Smf_PDUSess_ExtProblemDetails{Status: http.StatusForbidden, Cause: "PDUTYPE_DENIED"},
		N1SmMsg: &models.RefToBinaryData{ContentId: "n1SmMsg"},
	}
}

func testN1SmMsg() *multipart.RelatedContent {
	return &multipart.RelatedContent{ContentID: "n1SmMsg", Content: testPduSessionEstablishmentReject}
}

func TestCreateSmContextErrorAnswer(t *testing.T) {
	t.Parallel()

	answers := map[string]Nsmf_PDUSession.PostSmContextsError{
		"400": {PostSmContextsResponse400: &models.PostSmContextsResponse400{
			JsonData: testSmContextCreateError(), BinaryDataN1SmMessage: testN1SmMsg(),
		}},
		"403": {PostSmContextsResponse403: &models.PostSmContextsResponse403{
			JsonData: testSmContextCreateError(), BinaryDataN1SmMessage: testN1SmMsg(),
		}},
		"404": {PostSmContextsResponse404: &models.PostSmContextsResponse404{
			JsonData: testSmContextCreateError(), BinaryDataN1SmMessage: testN1SmMsg(),
		}},
		"500": {PostSmContextsResponse500: &models.PostSmContextsResponse500{
			JsonData: testSmContextCreateError(), BinaryDataN1SmMessage: testN1SmMsg(),
		}},
		"503": {PostSmContextsResponse503: &models.PostSmContextsResponse503{
			JsonData: testSmContextCreateError(), BinaryDataN1SmMessage: testN1SmMsg(),
		}},
		"504": {PostSmContextsResponse504: &models.PostSmContextsResponse504{
			JsonData: testSmContextCreateError(), BinaryDataN1SmMessage: testN1SmMsg(),
		}},
	}
	for status, answer := range answers {
		t.Run("SmContextCreateError "+status, func(t *testing.T) {
			t.Parallel()
			errorResponse, problemDetail, err := createSmContextErrorAnswer(
				openapi.GenericOpenAPIError{ErrorStatus: http.StatusForbidden, ErrorModel: answer})
			require.NoError(t, err, "an answer of the SMF is no error of the request")
			assert.Nil(t, problemDetail)
			require.NotNil(t, errorResponse)
			require.NotNil(t, errorResponse.BinaryDataN1SmMessage)
			assert.Equal(t, testPduSessionEstablishmentReject, errorResponse.BinaryDataN1SmMessage.Content)
		})
	}

	t.Run("ProblemDetails", func(t *testing.T) {
		t.Parallel()
		problem := &models.ProblemDetails{Status: http.StatusLengthRequired}
		errorResponse, problemDetail, err := createSmContextErrorAnswer(openapi.GenericOpenAPIError{
			ErrorStatus: http.StatusLengthRequired,
			ErrorModel:  Nsmf_PDUSession.PostSmContextsError{ProblemDetails: problem},
		})
		require.NoError(t, err)
		assert.Nil(t, errorResponse)
		assert.Equal(t, problem, problemDetail)
	})

	// The ProblemDetails body of a 503 (TS 29.500 5.2.7.2), as an SCP sends, decodes into an empty
	// PostSmContextsResponse503.
	notAnswers := map[string]Nsmf_PDUSession.PostSmContextsError{
		"redirect without a body":    {Location: "http://smf2/"},
		"ProblemDetails body on 503": {PostSmContextsResponse503: &models.PostSmContextsResponse503{}},
		"SmContextCreateError without its error": {PostSmContextsResponse403: &models.PostSmContextsResponse403{
			JsonData:              &models.Smf_PDUSess_SmContextCreateError{N1SmMsg: testSmContextCreateError().N1SmMsg},
			BinaryDataN1SmMessage: testN1SmMsg(),
		}},
	}
	for name, answer := range notAnswers {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			errorResponse, problemDetail, err := createSmContextErrorAnswer(
				openapi.GenericOpenAPIError{ErrorStatus: http.StatusServiceUnavailable, ErrorModel: answer})
			require.Error(t, err)
			assert.Nil(t, errorResponse)
			assert.Nil(t, problemDetail)
		})
	}

	t.Run("no answer", func(t *testing.T) {
		t.Parallel()
		errorResponse, problemDetail, err := createSmContextErrorAnswer(errors.New("connection refused"))
		require.Error(t, err)
		assert.Nil(t, errorResponse)
		require.NotNil(t, problemDetail)
		assert.Equal(t, int32(http.StatusInternalServerError), problemDetail.Status)
	})
}

// A 5GSM STATUS for session 5, PTI 0, cause #81 "invalid PTI value".
var testGsmStatus = []byte{0x2e, 0x05, 0x00, 0xd6, 0x51}

func testSmContextUpdateError() *models.Smf_PDUSess_SmContextUpdateError {
	return &models.Smf_PDUSess_SmContextUpdateError{
		Error:   &models.Smf_PDUSess_ExtProblemDetails{Status: http.StatusForbidden, Cause: "N1_SM_ERROR"},
		N1SmMsg: &models.RefToBinaryData{ContentId: "GSM_NAS"},
	}
}

func TestUpdateSmContextErrorAnswer(t *testing.T) {
	t.Parallel()

	n1 := func() *multipart.RelatedContent {
		return &multipart.RelatedContent{ContentID: "GSM_NAS", Content: testGsmStatus}
	}
	answers := map[string]Nsmf_PDUSession.UpdateSmContextError{
		"400": {UpdateSmContextResponse400: &models.UpdateSmContextResponse400{
			JsonData: testSmContextUpdateError(), BinaryDataN1SmMessage: n1(),
		}},
		"403": {UpdateSmContextResponse403: &models.UpdateSmContextResponse403{
			JsonData: testSmContextUpdateError(), BinaryDataN1SmMessage: n1(),
		}},
		"404": {UpdateSmContextResponse404: &models.UpdateSmContextResponse404{
			JsonData: testSmContextUpdateError(), BinaryDataN1SmMessage: n1(),
		}},
		"500": {UpdateSmContextResponse500: &models.UpdateSmContextResponse500{
			JsonData: testSmContextUpdateError(), BinaryDataN1SmMessage: n1(),
		}},
		"503": {UpdateSmContextResponse503: &models.UpdateSmContextResponse503{
			JsonData: testSmContextUpdateError(), BinaryDataN1SmMessage: n1(),
		}},
		"504": {UpdateSmContextResponse504: &models.UpdateSmContextResponse504{
			JsonData: testSmContextUpdateError(), BinaryDataN1SmMessage: n1(),
		}},
	}
	for status, answer := range answers {
		t.Run("SmContextUpdateError "+status, func(t *testing.T) {
			t.Parallel()
			errorResponse, problemDetail, err := updateSmContextErrorAnswer(
				openapi.GenericOpenAPIError{ErrorStatus: http.StatusForbidden, ErrorModel: answer})
			require.NoError(t, err, "an answer of the SMF is no error of the request")
			assert.Nil(t, problemDetail)
			require.NotNil(t, errorResponse)
			require.NotNil(t, errorResponse.BinaryDataN1SmMessage)
			assert.Equal(t, testGsmStatus, errorResponse.BinaryDataN1SmMessage.Content)
		})
	}

	t.Run("ProblemDetails", func(t *testing.T) {
		t.Parallel()
		problem := &models.ProblemDetails{Status: http.StatusLengthRequired}
		errorResponse, problemDetail, err := updateSmContextErrorAnswer(openapi.GenericOpenAPIError{
			ErrorStatus: http.StatusLengthRequired,
			ErrorModel:  Nsmf_PDUSession.UpdateSmContextError{ProblemDetails: problem},
		})
		require.NoError(t, err)
		assert.Nil(t, errorResponse)
		assert.Equal(t, problem, problemDetail)
	})

	notAnswers := map[string]Nsmf_PDUSession.UpdateSmContextError{
		"redirect without a body":    {Location: "http://smf2/"},
		"ProblemDetails body on 503": {UpdateSmContextResponse503: &models.UpdateSmContextResponse503{}},
		"SmContextUpdateError without its error": {UpdateSmContextResponse403: &models.UpdateSmContextResponse403{
			JsonData:              &models.Smf_PDUSess_SmContextUpdateError{N1SmMsg: testSmContextUpdateError().N1SmMsg},
			BinaryDataN1SmMessage: n1(),
		}},
	}
	for name, answer := range notAnswers {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			errorResponse, problemDetail, err := updateSmContextErrorAnswer(
				openapi.GenericOpenAPIError{ErrorStatus: http.StatusServiceUnavailable, ErrorModel: answer})
			require.Error(t, err)
			assert.Nil(t, errorResponse)
			assert.Nil(t, problemDetail)
		})
	}

	t.Run("no answer", func(t *testing.T) {
		t.Parallel()
		errorResponse, problemDetail, err := updateSmContextErrorAnswer(errors.New("connection refused"))
		require.Error(t, err)
		assert.Nil(t, errorResponse)
		require.NotNil(t, problemDetail)
		assert.Equal(t, int32(http.StatusInternalServerError), problemDetail.Status)
	})
}
