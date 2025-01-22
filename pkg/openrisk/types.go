package openrisk

import "github.com/projectdiscovery/openrisk/pkg/scorer"

type OpenRisk struct {
	Options *Options
	Scorer  *scorer.Scorer
}

type Options struct {
	ConfigFile string
}
