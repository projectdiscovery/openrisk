# openrisk

openrisk amûrek ceribandî ye ku derketina nuclei (text û markdown) dixwîne û bi karanîna modela GPT-3 ya OpenAI-ê ji bo host xala rîskê çêdike. Armanc ew e, ji bo niha, ku di demekê de li dijî yek hostê bixebite.

> NOTE: Ev bernameyek ceribandinê ye ku ji hêla Tîma Lêkolînê ya ProjectDiscovery ve hatî berdan. Bi vî rengî, dibe ku ew standardên kalîteya kodê wekî projeyên me yên din pêk neyne û dibe ku ew qas baş neyê ceribandin. Em pêşwaziya pêşniyaran, rastkirina xeletiyan, û ramanên li ser yekkirina van ceribandinan di nav amûrên me yên din de dikin!

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

experimental  
____  ____  ___  ____  _____(_)____/ /__
/ __ \/ __ \/ _ \/ __ \/ ___/ / ___/ //_/
/ /_/ / /_/ /  __/ / / / /  / (__  ) ,<   
\____/ .___/\___/_/ /_/_/  /_/____/_/|_|  Powered by OpenAI (GPT-3)
  /_/                                   
  
                projectdiscovery.io

  -i string
    	Nuclei scan result file or directory path. Supported file extensions: .txt, .md
```

### Hilberîna xala riskê

```sh
export OPENAI_API_KEY=<OPENAI_API_KEY>
openrisk -i nuclei_scan_result.txt
```

Nimûne derketin:

> The 10-scale risk score for the given Nuclei scan result is 10. This is because all of the vulnerabilities listed are rated as either critical or high, which are the two highest risk levels.
