# openrisk
openrisk is a tool that generates a risk score based on the results of a Nuclei scan. 


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

experimental  
____  ____  ___  ____  _____(_)____/ /__
/ __ \/ __ \/ _ \/ __ \/ ___/ / ___/ //_/
/ /_/ / /_/ /  __/ / / / /  / (__  ) ,<   
\____/ .___/\___/_/ /_/_/  /_/____/_/|_|  Powered by OpenAI (GPT-3)
  /_/                                   
  
                projectdiscovery.io

  -i string
        Nuclei scan result file path
```

### Generating risk score

```sh
export OPENAI_API_KEY=<OPENAI_API_KEY>
openrisk -i nuclei_scan_result.txt
```

Example output:

```console
The 10-scale risk score for the given Nuclei scan result is 10. This is because all of the vulnerabilities listed are rated as either critical or high, which are the two highest risk levels.
```
