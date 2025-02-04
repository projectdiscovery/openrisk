package openrisk

import (
	"os"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/openrisk/pkg/scorer"
)

func New(options *Options) (*OpenRisk, error) {
	scorer, err := buildScorer(options.ConfigFile)
	if err != nil {
		return nil, err
	}

	openRisk := &OpenRisk{
		Options: options,
		Scorer:  scorer,
	}
	return openRisk, nil

}

func buildScorer(configFlag string) (*scorer.Scorer, error) {
	if configFlag == "" {
		return scorer.FromDefaultConfig(), nil
	}

	cf, err := os.Open(configFlag)
	if err != nil {
		gologger.Error().Msgf("Failed to open config file: %s. Error: %v\n", configFlag, err)
		return nil, err
	}
	defer cf.Close()

	s, err := scorer.FromConfig(scorer.NameFromFilepath(configFlag), cf)
	if err != nil {
		gologger.Error().Msgf("Failed to build scorer from config file: %s. Error: %v\n", configFlag, err)
		return nil, err
	}
	return s, nil
}
