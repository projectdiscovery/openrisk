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
	CriticalVulnerability int
	HighVulnerability     int
	MediumVulnerability   int
	LowVulnerability      int
	UnknownVulnerability  int
	IsCVE                 int
	IsKEV                 int
	TotalAssets           int
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
			signals.TotalAssets++
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	signalsMap := map[string]string{
		"critical_vulnerability": strconv.Itoa(signals.CriticalVulnerability),
		"high_vulnerability":     strconv.Itoa(signals.HighVulnerability),
		"medium_vulnerability":   strconv.Itoa(signals.MediumVulnerability),
		"low_vulnerability":      strconv.Itoa(signals.LowVulnerability),
		"unknown_vulnerability":  strconv.Itoa(signals.UnknownVulnerability),
		"total_cve":              strconv.Itoa(signals.IsCVE),
		"total_kev":              strconv.Itoa(signals.IsKEV),
		"total_assets":           strconv.Itoa(signals.TotalAssets),
	}

	return signalsMap, nil
}

type SignalData struct {
	OpenVulnerability struct {
		SeverityBreakdown struct {
			Critical int `json:"critical"`
			High     int `json:"high"`
			Medium   int `json:"medium"`
			Low      int `json:"low"`
			Unknown  int `json:"unknown"`
		} `json:"severity_breakdown"`
		TotalAssets int `json:"total_assets"`
		IsCVE       int `json:"total_cve,omitempty"`
		IsKEV       int `json:"total_kev,omitempty"`
	} `json:"open_vulnerability"`
}

func ParseSignalsFromJson(filePath string) (map[string]string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var data SignalData
	if err := json.NewDecoder(file).Decode(&data); err != nil {
		return nil, err
	}

	return map[string]string{
		"critical_vulnerability": strconv.Itoa(data.OpenVulnerability.SeverityBreakdown.Critical),
		"high_vulnerability":     strconv.Itoa(data.OpenVulnerability.SeverityBreakdown.High),
		"medium_vulnerability":   strconv.Itoa(data.OpenVulnerability.SeverityBreakdown.Medium),
		"low_vulnerability":      strconv.Itoa(data.OpenVulnerability.SeverityBreakdown.Low),
		"unknown_vulnerability":  strconv.Itoa(data.OpenVulnerability.SeverityBreakdown.Unknown),
		"total_cve":              strconv.Itoa(data.OpenVulnerability.IsCVE),
		"total_kev":              strconv.Itoa(data.OpenVulnerability.IsKEV),
		"total_assets":           strconv.Itoa(data.OpenVulnerability.TotalAssets),
	}, nil
}
