# openrisk

openrisk is an experimental tool which reads nuclei output (text and markdown) and generates a risk score for the host using OpenAI's GPT-3 model. It is intended, for now, to work against a single target at a time.

> NOTE: This is an experimental program released by the ProjectDiscovery Research Team. As such, it may not meet the same code quality standards as our other projects, and may not be as well-tested. We welcome suggestions, bug fixes, and ideas on integrating these experiments into our other tools!

# Install openrisk
openrisk requires **go1.18** to install successfully. Run the following command to install the latest version -

```sh
go install -v github.com/projectdiscovery/openrisk
```

### Usage

```sh
openrisk -h
```

```console

____  ____  ___  ____  _____(_)____/ /__
/ __ \/ __ \/ _ \/ __ \/ ___/ / ___/ //_/
/ /_/ / /_/ /  __/ / / / /  / (__  ) ,<   
\____/ .___/\___/_/ /_/_/  /_/____/_/|_| Powered by OpenAI (GPT-3)
  /_/ PD Research Experiment
  
                projectdiscovery.io

  -i string
        Nuclei scan result file or directory path. Supported file extensions: .txt, .md
```

### Generating risk score

```sh
export OPENAI_API_KEY=<OPENAI_API_KEY>
openrisk -i nuclei_scan_result.txt
```

Example output:

> The 10-scale risk score for the given Nuclei scan result is 10. This is because all of the vulnerabilities listed are rated as either critical or high, which are the two highest risk levels.
