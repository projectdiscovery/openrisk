package openrisk

type IssueParser interface {
	Parse(nucleiScanResult []byte) (string, error)
}
