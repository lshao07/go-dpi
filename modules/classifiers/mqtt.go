package classifiers

import (
	"strings"

	"github.com/dreadl0ck/gopacket"
	"github.com/dreadl0ck/gopacket/layers"
	"github.com/dreadl0ck/go-dpi/types"
)

// MQTTClassifier struct
type MQTTClassifier struct{}

// HeuristicClassify for MQTTClassifier
func (classifier MQTTClassifier) HeuristicClassify(flow *types.Flow) bool {
	return checkFirstPayload(flow.GetPackets(), layers.LayerTypeTCP,
		func(payload []byte, packetsRest []gopacket.Packet) bool {
			//check Control packet (connect)
			isValidPacket := payload[0] == 0x10
			//check message lenght
			isValidLenght := int(payload[1]) == len(payload[2:])
			if len(payload) < 4 {
				return false
			}
			protocolNameStr := string(payload[4:])
			//check protocol name
			isValidMQTT := strings.HasPrefix(protocolNameStr, "MQ")
			return isValidMQTT && isValidLenght && isValidPacket
		})
}

// GetProtocol returns the corresponding protocol
func (classifier MQTTClassifier) GetProtocol() types.Protocol {
	return types.MQTT
}
