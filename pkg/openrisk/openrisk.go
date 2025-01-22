package openrisk

import (
	"errors"
	"os"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/openrisk/pkg/scorer"
)

func New(options *Options) (*OpenRisk, error) {
	if options.ConfigFile == "" {
		return nil, errors.New("config file must be set")
	}
	openRisk := &OpenRisk{
		Options: options,
		Scorer:  buildScorer(options.ConfigFile),
	}
	return openRisk, nil

}

func buildScorer(configFlag string) *scorer.Scorer {
	var s *scorer.Scorer
	cf, err := os.Open(configFlag)
	if err != nil {
		gologger.Error().Msgf("Failed to open config file: %s. Error: %v\n", configFlag, err)
		os.Exit(2)
	}
	defer cf.Close()

	s, err = scorer.FromConfig(scorer.NameFromFilepath(configFlag), cf)
	if err != nil {
		gologger.Error().Msgf("Failed to build scorer from config file: %s. Error: %v\n", configFlag, err)
		os.Exit(2)
	}
	return s
}
