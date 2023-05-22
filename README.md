<h1 align="center">
  openrisk
<br>
</h1>


openrisk is an experimental tool which reads [nuclei](http://github.com/projectdiscovery/nuclei) output (text, markdown, and JSON) and generates a risk score for the host using OpenAI's GPT-3 model. It is intended, for now, to work against a single target at a time.

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
\____/ .___/\___/_/ /_/_/  /_/____/_/|_|  Powered by OpenAI (GPT-3)
    /_/                                   v0.0.1 (experimental)  
                projectdiscovery.io

 openrisk is an experimental tool generates a risk score from nuclei output for the host using OpenAI's GPT-3 model.

Usage:
  openrisk [flags]

Flags:
INPUT:
   -f, -files string[]  Nuclei scan result file or directory path. Supported file extensions: .txt, .md, .jsonl
```

> **NOTE**: `OPENAI_API_KEY` is required to run this program and can be obtained by signing up at `https://openai.com/api/`

### Generating Risk Score

```sh
export OPENAI_API_KEY=<OPENAI_API_KEY>

openrisk -f nuclei_scan_result.txt
```

### Example Run:

```console
openrisk -f nuclei_results.txt

                               _      __  
  ____  ____  ___  ____  _____(_)____/ /__
 / __ \/ __ \/ _ \/ __ \/ ___/ / ___/ //_/
/ /_/ / /_/ /  __/ / / / /  / (__  ) ,<   
\____/ .___/\___/_/ /_/_/  /_/____/_/|_|  Powered by OpenAI (GPT-3)
    /_/                                   v0.0.1 (experimental)                                          
  
    projectdiscovery.io

[RISK SCORE] The 10-scale risk score for the Nuclei scan results is 10. There are multiple high-severity vulnerabilities related to Pantheon, AWS, and Netlify takeovers.
```

### Using `openrisk` as a library

To utilize `openrisk` as a library, simply create an instance of the `Options` structure and input your OpenAI API key. With these options, you can then create `OpenRisk` and `IssueProcessor` by including a sample nuclei scan result file. To generate a score for the sample file, call the `openRisk.GetScore` function. For a clear example, refer to the code provided in the [examples](examples/) folder.