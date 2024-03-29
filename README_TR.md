# openrisk

openrisk, nuclei çıktısını (text ve markdown) okuyan ve OpenAI'nin GPT-3 modelini kullanarak host için bir risk puanı oluşturan deneysel bir araçtır. Şimdilik, tek seferde tek bir host -a karşı çalışması amaçlanıyor.

> **NOT**: Bu, ProjectDiscovery Araştırma Ekibi tarafından yayınlanan deneysel bir programdır. Bu nedenle, diğer projelerimizle aynı kod kalite standartlarını karşılamayabilir ve iyi test edilmemiş olabilir. Önerilere, hata düzeltmelerine ve bu deneyleri diğer araçlarımıza entegre etmeye yönelik fikirlere açığız!

# openrisk'i yükleyin
openrisk'in başarıyla yüklenmesi için **g20** gereklidir. En son sürümü yüklemek için aşağıdaki komutu çalıştırın -

```sh
go install -v github.com/projectdiscovery/openrisk
```

### Kullanım

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

Usage:
  openrisk [flags]

Flags:
INPUT:
   -f, -files string[]  Nuclei scan result file or directory path. Supported file extensions: .txt, .md, .jsonl
```

### Risk puanı oluşturma

```sh
export OPENAI_API_KEY=<OPENAI_API_KEY>
openrisk -f nuclei_scan_result.txt
```

Örnek çıktı:

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

### `openrisk`'i bir kütüphane olarak kullanma

`openrisk`'i bir kütüphane olarak kullanmak için, `Options` örneği oluşturun ve OpenAI API anahtarınızı girin. Bu seçeneklerle, örnek bir nuclei tarama sonuç dosyasını dahil ederek `OpenRisk` ve `IssueProcessor`'u oluşturabilirsiniz. Örnek dosya için bir puan oluşturmak için, `openRisk.GetScore` fonksiyonunu çağırın. Açık bir örnek için, [örnekler](examples/) klasöründeki sağlanan koda bakın.
