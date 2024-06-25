package processor

import (
	"github.com/free5gc/amf/internal/sbi/consumer"
	"github.com/free5gc/amf/pkg/app"
)

type ProcessorAmf interface {
	app.App

	Consumer() *consumer.Consumer
}

type Processor struct {
	ProcessorAmf
	consumer *consumer.Consumer
}

func NewProcessor(amf ProcessorAmf) (*Processor, error) {
	p := &Processor{
		ProcessorAmf: amf,
		consumer:     amf.Consumer(),
	}
	return p, nil
}

func (p *Processor) Consumer() *consumer.Consumer {
	return p.consumer
}
