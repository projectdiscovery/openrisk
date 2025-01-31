package openrisk

import (
	"bytes"
	"os"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/openrisk/pkg/scorer"
)

func New(options *Options) (*OpenRisk, error) {
	var scorer *scorer.Scorer
	if options.RawConfig != nil {
		scorer = buildScorerFromRawConfig(options.RawConfig)
	} else {
		scorer = buildScorerFromConfigFile(options.ConfigFile)
	}

	openRisk := &OpenRisk{
		Options: options,
		Scorer:  scorer,
	}
	return openRisk, nil

}

func buildScorerFromConfigFile(configFlag string) *scorer.Scorer {
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

func buildScorerFromRawConfig(rawConfig []byte) *scorer.Scorer {
	reader := bytes.NewReader(rawConfig)
	s, err := scorer.FromConfig("raw", reader)
	if err != nil {
		gologger.Error().Msgf("Failed to build scorer from raw config. Error: %v\n", err)
		os.Exit(2)
	}
	return s
}
