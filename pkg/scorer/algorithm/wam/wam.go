package wam

import "github.com/projectdiscovery/openrisk/pkg/scorer/algorithm"

type WeighetedArithmeticMean struct {
	inputs []*algorithm.Input
}

// New returns a new instance of the Weighted Arithmetic Mean algorithm, which
// is used by the Pike algorithm.
func New(inputs []*algorithm.Input) (algorithm.Algorithm, error) {
	return &WeighetedArithmeticMean{
		inputs: inputs,
	}, nil
}

func (p *WeighetedArithmeticMean) Score(record map[string]float64) float64 {
	var totalWeight float64
	var s float64
	for _, i := range p.inputs {
		v, ok := i.Value(record)
		if !ok {
			continue
		}
		totalWeight += i.Weight
		s += i.Weight * v
	}
	return s / totalWeight
}

func init() {
	algorithm.Register("weighted_arithmetic_mean", New)
}
