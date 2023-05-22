package openrisk

type TxtIssueParser struct {
}

func NewTxtIssueParser() *TxtIssueParser {
	return &TxtIssueParser{}
}

func (tip *TxtIssueParser) Parse(nucleiScanResult []byte) (string, error) {
	return string(nucleiScanResult), nil
}
