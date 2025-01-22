package scorer

import (
	"bytes"
	_ "embed"
)

const defaultScoreName = "default_score"

//go:embed default_config.yml
var defaultConfigContent []byte

func FromDefaultConfig() *Scorer {
	r := bytes.NewReader(defaultConfigContent)
	s, err := FromConfig(defaultScoreName, r)
	if err != nil {
		panic(err)
	}
	return s
}
