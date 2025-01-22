package openrisk

import (
	"os"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/openrisk/pkg/scorer"
)

func New(options *Options) (*OpenRisk, error) {
	openRisk := &OpenRisk{
		Options: options,
		Scorer:  buildScorer(options.ConfigFile),
	}
	return openRisk, nil

}

func buildScorer(configFlag string) *scorer.Scorer {
	if configFlag == "" {
		return scorer.FromDefaultConfig()
	}

	cf, err := os.Open(configFlag)
	if err != nil {
		gologger.Error().Msgf("Failed to open config file: %s. Error: %v\n", configFlag, err)
		os.Exit(2)
	}
	defer cf.Close()

	s, err := scorer.FromConfig(scorer.NameFromFilepath(configFlag), cf)
	if err != nil {
		gologger.Error().Msgf("Failed to build scorer from config file: %s. Error: %v\n", configFlag, err)
		os.Exit(2)
	}
	return s
}
