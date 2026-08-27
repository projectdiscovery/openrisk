<h1 align="center">
  openrisk
<br>
</h1>

openrisk는 [nuclei](http://github.com/projectdiscovery/nuclei) 출력 결과(text, markdown, JSON)를 읽고 OpenAI의 **GPT-4o 모델**을 사용하여 호스트의 **위험 점수(risk score)** 를 생성하는 실험적 도구입니다. 현재는 **단일 대상(single target)** 에 대해서만 동작하도록 설계되었습니다.

> **주의**: 이 프로그램은 ProjectDiscovery Research Team에서 실험적으로 배포한 것입니다. 따라서 다른 프로젝트들에 비해 코드 품질이 낮을 수 있으며, 충분히 테스트되지 않았을 수 있습니다. 버그 수정, 기능 개선 아이디어, 다른 도구와의 통합 방안 제안을 환영합니다!

---

### 설치 방법

openrisk는 설치 시 **go1.20** 이상이 필요합니다. 최신 버전을 설치하려면 다음 명령어를 실행하세요:

```sh
go install -v github.com/projectdiscovery/openrisk@latest
```

### 사용 방법

```sh
openrisk -h
```

```console
                               _      __  
  ____  ____  ___  ____  _____(_)____/ /__
 / __ \/ __ \/ _ \/ __ \/ ___/ / ___/ //_/
/ /_/ / /_/ /  __/ / / / /  / (__  ) ,<   
\____/ .___/\___/_/ /_/_/  /_/____/_/|_|  Powered by OpenAI (GPT-4o)
    /_/                                   v0.0.1 (experimental)  
                projectdiscovery.io

 openrisk is an experimental tool generates a risk score from nuclei output for the host using OpenAI's GPT-4o model.

Usage:
  openrisk [flags]

Flags:
INPUT:
   -f, -files string[]  Nuclei scan result file or directory path. Supported file extensions: .txt, .md, .jsonl
```

> **주의**: 실행을 위해 OPENAI_API_KEY 환경변수가 필요합니다.
키는 https://openai.com/api/ 에서 발급받을 수 있습니다.

### 위험 점수 생성하기

```sh
export OPENAI_API_KEY=<OPENAI_API_KEY>

openrisk -f nuclei_scan_result.txt
```

### 실행 예시

```console
openrisk -f nuclei_results.txt

                               _      __  
  ____  ____  ___  ____  _____(_)____/ /__
 / __ \/ __ \/ _ \/ __ \/ ___/ / ___/ //_/
/ /_/ / /_/ /  __/ / / / /  / (__  ) ,<   
\____/ .___/\___/_/ /_/_/  /_/____/_/|_|  Powered by OpenAI (GPT-4o)
    /_/                                   v0.0.1 (experimental)                                          
  
    projectdiscovery.io

[RISK SCORE] The 10-scale risk score for the Nuclei scan results is 10.There are multiple high-severity vulnerabilities related to Pantheon, AWS, and Netlify takeovers.
```

### `openrisk`를 라이브러리로 사용하기

`openrisk`를 라이브러리로 활용하려면, 먼저 `Options` 구조체를 생성하고 OpenAI API 키를 입력해야 합니다.
이 옵션을 이용해 `OpenRisk`와 `IssueProcessor`를 생성하고, 샘플 nuclei 결과 파일을 포함할 수 있습니다.
샘플 파일에 대한 점수를 생성하려면 `openRisk.GetScore` 함수를 호출하세요.
구체적인 예시는 [examples](examples/) 폴더에 있는 코드를 참고하세요.