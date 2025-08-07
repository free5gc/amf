 package util

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gitlab.tsipl.com/5g/openapi/models"
)

func TestSnssaiHexToModels(t *testing.T) {
	t.Run("valid hex string with SST and SD", func(t *testing.T) {
		hexStr := "01112233" // SST = 0x01 (1), SD = "112233"
		expected := &models.Snssai{
			Sst: 1,
			Sd:  "112233",
		}

		snssai, err := SnssaiHexToModels(hexStr)
		require.NoError(t, err)
		assert.Equal(t, expected, snssai)
	})

	t.Run("invalid hex string for SST", func(t *testing.T) {
		hexStr := "ZZ112233" // invalid SST hex

		snssai, err := SnssaiHexToModels(hexStr)
		assert.Nil(t, snssai)
		assert.Error(t, err)
	})
}
func TestSnssaiModelsToHex(t *testing.T) {
	t.Run("valid Snssai with Sst and Sd", func(t *testing.T) {
		snssai := models.Snssai{
			Sst: 1,
			Sd:  "112233",
		}
		expected := "01112233" // 01 (hex of 1) + Sd

		hexStr := SnssaiModelsToHex(snssai)
		assert.Equal(t, expected, hexStr)
	})

	t.Run("Sst with double digit value", func(t *testing.T) {
		snssai := models.Snssai{
			Sst: 26,
			Sd:  "abcdef",
		}
		expected := "1aabcdef" // 1a is hex of 26

		hexStr := SnssaiModelsToHex(snssai)
		assert.Equal(t, expected, hexStr)
	})

	t.Run("empty Sd field", func(t *testing.T) {
		snssai := models.Snssai{
			Sst: 15,
			Sd:  "",
		}
		expected := "0f" // just the hex of 15

		hexStr := SnssaiModelsToHex(snssai)
		assert.Equal(t, expected, hexStr)
	})
}
func TestSeperateAmfId(t *testing.T) {
	t.Run("valid AMF ID", func(t *testing.T) {
		amfid := "12a1b2" // regionId = "12", rest = a1b2

		regionId, setId, ptrId, err := SeperateAmfId(amfid)

		assert.NoError(t, err)
		assert.Equal(t, "12", regionId)
		assert.Equal(t, "286", setId) // derived from bits
		assert.Equal(t, "32", ptrId)  // derived from bits
	})

	t.Run("invalid AMF ID length", func(t *testing.T) {
		amfid := "1234"

		regionId, setId, ptrId, err := SeperateAmfId(amfid)

		assert.Error(t, err)
		assert.Empty(t, regionId)
		assert.Empty(t, setId)
		assert.Empty(t, ptrId)
	})

	t.Run("invalid AMF ID hex characters", func(t *testing.T) {
		amfid := "12zzzz" // invalid hex in last 4 characters

		regionId, setId, ptrId, err := SeperateAmfId(amfid)

		assert.Error(t, err)
		assert.Equal(t, "12", regionId)
		assert.Empty(t, setId)
		assert.Empty(t, ptrId)
	})
}

func TestPlmnIdStringToModels(t *testing.T) {
	t.Run("valid 5-digit PLMN ID", func(t *testing.T) {
		plmnStr := "28393" // MCC: 310, MNC: 15

		expected := models.PlmnId{
			Mcc: "283",
			Mnc: "93",
		}

		result := PlmnIdStringToModels(plmnStr)

		assert.Equal(t, expected, result)
	})

	t.Run("valid 6-digit PLMN ID", func(t *testing.T) {
		plmnStr := "460011" // MCC: 460, MNC: 011

		expected := models.PlmnId{
			Mcc: "460",
			Mnc: "011",
		}

		result := PlmnIdStringToModels(plmnStr)

		assert.Equal(t, expected, result)
	})

	t.Run("invalid PLMN ID (too short)", func(t *testing.T) {
		plmnStr := "12" // invalid

		defer func() {
			if r := recover(); r == nil {
				t.Error("Expected panic due to short plmnId, but function did not panic")
			}
		}()

		_ = PlmnIdStringToModels(plmnStr) // should panic on plmnId[:3]
	})
}
func TestTACConfigToModels(t *testing.T) {
	t.Run("valid TAC integer string", func(t *testing.T) {
		input := "12345"
		expected := "003039" // 12345 in hex is 0x3039

		result := TACConfigToModels(input)

		assert.Equal(t, expected, result)
	})

	t.Run("maximum 3-byte TAC value", func(t *testing.T) {
		input := "16777215" // 0xFFFFFF
		expected := "ffffff"

		result := TACConfigToModels(input)

		assert.Equal(t, expected, result)
	})

	t.Run("invalid TAC string (non-numeric)", func(t *testing.T) {
		input := "abc"

		result := TACConfigToModels(input)

		// When ParseUint fails, it logs and returns empty hex string
		assert.Equal(t, "000000", result) // because tmp is 0 if err != nil
	})
}
