package openrisk

import (
	"bufio"
	"encoding/json"
	"os"
	"strconv"
	"strings"

	sliceutil "github.com/projectdiscovery/utils/slice"
)

type Record struct {
	Info struct {
		Severity string   `json:"severity"`
		Tags     []string `json:"tags"`
	} `json:"info"`
	Host string `json:"host"`
}

type Signals struct {
	TotalVulnerability    int
	CriticalVulnerability int
	HighVulnerability     int
	MediumVulnerability   int
	LowVulnerability      int
	UnknownVulnerability  int
	IsCVE                 int
	IsKEV                 int
	TotalAsset            int
}

func ParseSignals(filePath string) (map[string]string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	signals := Signals{}
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		var record Record
		if err := json.Unmarshal([]byte(line), &record); err != nil {
			continue
		}

		switch strings.ToLower(record.Info.Severity) {
		case "critical":
			signals.CriticalVulnerability++
		case "high":
			signals.HighVulnerability++
		case "medium":
			signals.MediumVulnerability++
		case "low":
			signals.LowVulnerability++
		default:
			signals.UnknownVulnerability++
		}

		if sliceutil.Contains(record.Info.Tags, "cve") {
			signals.IsCVE++
		}
		if sliceutil.Contains(record.Info.Tags, "kev") {
			signals.IsKEV++
		}

		if record.Host != "" {
			signals.TotalAsset++
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	signals.TotalVulnerability = signals.CriticalVulnerability + signals.HighVulnerability + signals.MediumVulnerability + signals.LowVulnerability + signals.UnknownVulnerability

	signalsMap := map[string]string{
		"total_vulnerability":    strconv.Itoa(signals.TotalVulnerability),
		"critical_vulnerability": strconv.Itoa(signals.CriticalVulnerability),
		"high_vulnerability":     strconv.Itoa(signals.HighVulnerability),
		"medium_vulnerability":   strconv.Itoa(signals.MediumVulnerability),
		"low_vulnerability":      strconv.Itoa(signals.LowVulnerability),
		"unknown_vulnerability":  strconv.Itoa(signals.UnknownVulnerability),
		"total_cve":              strconv.Itoa(signals.IsCVE),
		"total_kve":              strconv.Itoa(signals.IsKEV),
		"total_asset":            strconv.Itoa(signals.TotalAsset),
	}

	return signalsMap, nil
}
