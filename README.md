<h1 align="center">
  openrisk
<br>
</h1>


openrisk is an experimental tool which reads [nuclei](http://github.com/projectdiscovery/nuclei) output (JSONL) and generates a risk score for the scan. It is intended, for now, to work against a single scan at a time.

> **NOTE**: This is an experimental program released by the ProjectDiscovery Research Team. As such, it may not meet the same code quality standards as our other projects, and may not be as well-tested. We welcome suggestions, bug fixes, and ideas on integrating these experiments into our other tools!

### Install openrisk
openrisk requires **go1.20** to install successfully. Run the following command to install the latest version -

```sh
go install -v github.com/projectdiscovery/openrisk@latest
```

### Usage

```sh
openrisk -h
```

```console
                               _      __  
  ____  ____  ___  ____  _____(_)____/ /__
 / __ \/ __ \/ _ \/ __ \/ ___/ / ___/ //_/
/ /_/ / /_/ /  __/ / / / /  / (__  ) ,<   
\____/ .___/\___/_/ /_/_/  /_/____/_/|_|
    /_/                                   v0.0.1 (experimental)  
                projectdiscovery.io

 openrisk is an experimental tool generates a risk score from nuclei output for the scan.

Usage:
  openrisk [flags]

Flags:
INPUT:
   -sf, -scan-file string  Nuclei scan result file (JSON only, required)
   -c, -config string      the filename of the config (required)
```


### Generating Risk Score

```sh
export OPENAI_API_KEY=<OPENAI_API_KEY>

openrisk -f nuclei_scan_result.txt
```

### Example Run:

```console
openrisk -c default_config.yml -sf result.jsonl

                               _      __  
  ____  ____  ___  ____  _____(_)____/ /__
 / __ \/ __ \/ _ \/ __ \/ ___/ / ___/ //_/
/ /_/ / /_/ /  __/ / / / /  / (__  ) ,<   
\____/ .___/\___/_/ /_/_/  /_/____/_/|_|
    /_/                                   v0.0.1 (experimental)                                          
  
    projectdiscovery.io

[RISK SCORE] 0.6221876600
```


