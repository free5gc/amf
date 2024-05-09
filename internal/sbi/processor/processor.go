package processor

import (
	"github.com/free5gc/amf/internal/sbi/consumer"
	"github.com/free5gc/amf/pkg/app"
)

type ProcessorAmf interface {
	app.App
}

type Processor struct {
	ProcessorAmf
	consumer *consumer.Consumer
}

type HandlerResponse struct {
	Status  int
	Headers map[string][]string
	Body    interface{}
}

func NewProcessor(amf ProcessorAmf) (*Processor, error) {
	p := &Processor{
		ProcessorAmf: amf,
	}
	return p, nil
}
