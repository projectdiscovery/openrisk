# openrisk

openrisk amûrek ceribandî ye ku derketina nuclei (text û markdown) dixwîne û bi karanîna modela GPT-3 ya OpenAI-ê ji bo host xala rîskê çêdike. Armanc ew e, ji bo niha, ku di demekê de li dijî yek hostê bixebite.

> **NOTE**: Ev bernameyek ceribandinê ye ku ji hêla Tîma Lêkolînê ya ProjectDiscovery ve hatî berdan. Bi vî rengî, dibe ku ew standardên kalîteya kodê wekî projeyên me yên din pêk neyne û dibe ku ew qas baş neyê ceribandin. Em pêşwaziya pêşniyaran, rastkirina xeletiyan, û ramanên li ser yekkirina van ceribandinan di nav amûrên me yên din de dikin!

# openrisk saz bikin
openrisk pêdivî ye ku **go1.18** bi serfirazî were saz kirin. Fermana jêrîn bicîh bikin ku guhertoya herî dawî saz bikin -

```sh
go install -v github.com/projectdiscovery/openrisk
```

### Bikaranîn

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

    -f value
        Nuclei scan result file or directory path. Supported file extensions: .txt, .md, .jsonl
    -files value
        Nuclei scan result file or directory path. Supported file extensions: .txt, .md, .jsonl
```

### Hilberîna xala riskê

```sh
export OPENAI_API_KEY=<OPENAI_API_KEY>
openrisk -f nuclei_scan_result.txt
```

Nimûne derketin:

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

### `openrisk`-ê wek library bikar anîn
Ji bo bikaranîna `openrisk` wek libraryê, nimûne yekê ji `Options` ava bikin û keya API'yê ya OpenAI'yê tevlî bikin. Bi tevlîkirina pelê encama skanê ya nimûneyê ya nuclei hûn dikarin `OpenRisk` û `IssueProcessor` biafirînin. Ji bo çêkirina xala rîskê ji bo pelê nimûneyê, bang fonksiyona `openRisk.GetScore` bikin. Ji bo nimûne yekê ya diyar, referansa koda ku di peldanka [examples](examples/) de hatiye dayîn bikin.
