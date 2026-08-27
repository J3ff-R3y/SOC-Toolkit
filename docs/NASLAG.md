# Naslag: Jeffrey Toolkit v1.0

Achtergronddocument over hoe de Jeffrey Toolkit als geheel werkt. Voor
snelle installatie-stappen, zie de [`README.md`](../README.md) in de
repo-root.

Je hebt geen voorkennis van dit project nodig om dit document te
volgen, maar wel basisvaardigheid met een Linux-terminal (SSH, `sudo`,
bestanden kopiëren).

## 1. Wat is de Jeffrey Toolkit?

Een lokale, browser-gebaseerde chatinterface tegen een taalmodel (een
AI-model zoals achter ChatGPT, maar dan volledig **lokaal draaiend**,
zonder dat er iets naar internet gaat). Collega's gebruiken hem in de
browser voor SOC- en ISO-gerelateerde vragen.

Waarom lokaal en niet gewoon ChatGPT of iets vergelijkbaars? De server
is bewust **air-gapped** — hij heeft geen internetverbinding. Dat is
een bewuste keuze: gevoelige SOC-vragen en -data verlaten het netwerk
nooit. Dit betekent ook dat elke aanpassing (nieuw model, nieuwe
software) via een omweg naar de server moet: downloaden op een andere
machine, dan overzetten via `scp`.

### De twee bouwstenen

| Onderdeel | Wat het is | Waar het staat |
|---|---|---|
| **Het taalmodel + server-software** | Het "brein" — een programma genaamd `llama-server` dat het model inlaadt en vragen beantwoordt via een technische interface (API) | `/opt/llama-server/` (programma), `/data/models/` (modelbestanden) |
| **De webpagina** | Wat collega's in hun browser zien en gebruiken | `/data/toolkit/index.html` |

Deze twee praten met elkaar via het netwerk **op de server zelf** (niet
naar buiten): de webpagina stuurt vragen naar `llama-server`, die
draait onveranderlijk op poort `8081`, alleen bereikbaar vanaf de
server zelf (`127.0.0.1`, "localhost"). Een losse webserver, **Apache**
(het programma `httpd`), zorgt dat collega's de pagina via hun browser
kunnen bereiken (poort `8080`) en stuurt hun vragen door naar
`llama-server` op de achtergrond.

```
Collega's browser  →  Apache (poort 8080)  →  llama-server (poort 8081, alleen lokaal)
                       serveert index.html      beantwoordt de vraag met het model
```

## 2. Bestandsoverzicht (op de server)

### `/data/toolkit/` — de webpagina (Apache's "DocumentRoot")

| Bestand | Doel |
|---|---|
| `index.html` | **De live pagina.** Dit is wat Apache daadwerkelijk aan bezoekers laat zien. |
| `jeffrey-v1.0.html` | **Werkkopie.** Bij een aanpassing aan de pagina (nieuwe functie, bugfix) wordt éérst dit bestand bewerkt en getest. Pas als het goed werkt, wordt het gekopieerd naar `index.html` (`cp jeffrey-v1.0.html index.html`). Zo staat er nooit een halve/kapotte wijziging live. |
| `xlsx.full.min.js` | JavaScript-bibliotheek voor Excel-parsing in de browser (SheetJS). |
| `pdf.min.mjs` / `pdf.worker.min.mjs` | PDF.js — client-side tekst-extractie uit geüploade PDF-bestanden. |

**Vuistregel:** wil je iets aan de pagina zelf veranderen (tekst, uiterlijk, functionaliteit)? Bewerk dan `jeffrey-v1.0.html`, test die grondig, en kopieer hem pas dan naar `index.html`.

### `/data/models/` — de modelbestanden

```bash
sudo ls -lh /data/models/
```

Hier staan de eigenlijke AI-modelbestanden (`.gguf`-bestanden, vaak
10-25 GB per stuk). Deze map is met opzet **niet zomaar beschrijfbaar**
(rechten `root:root`, modus `750`) — een verkeerd geplaatst of half
overgezet modelbestand zou de productieservice kunnen breken.

### `/data/scripts/` — onderhoudsgereedschap

Bevat `update-model.sh` (het script om het taalmodel te vervangen) en
een `README.md` met de exacte stappen daarbij.

## 3. Een paar technische begrippen kort uitgelegd

**systemd / service** — RHEL gebruikt `systemd` om
achtergrondprogramma's ("services") te beheren. `llama-server` draait
als `llama-server.service`. Commando's zoals
`sudo systemctl status llama-server` sturen die service aan.

**De "override"** — in plaats van het hoofdbestand van de service
rechtstreeks te wijzigen, gebruiken we een override: een klein, apart
bestand dat alleen de regel overschrijft die bepaalt *welk model* en
*met welke instellingen* `llama-server` opstart:
```
/etc/systemd/system/llama-server.service.d/override.conf
```
Dit is het bestand dat je aanpast bij een model-update — niet de
service zelf. (Deze publieke repo bevat geen kopie van dit bestand —
het bevat infrastructuurdetails die niet publiek hoeven te staan.)

**Logging — let op:** deze service logt bewust **niet** naar de
systemd-journal (`journalctl`), maar naar een los bestand:
```
/var/log/llama-server.log
```
Dit bestand bevat ook de timing-informatie per request (`prompt eval
time`, `eval time`) — nuttig bij het beoordelen van snelheid/prestaties.

**GGUF** — het bestandsformaat waarin AI-taalmodellen hier worden
opgeslagen. Eén bestand = één compleet model.

**Chat-template** — een technisch "recept" dat bepaalt hoe een vraag
precies wordt opgemaakt voordat die naar het model gaat. Elk model
verwacht mogelijk een net iets ander recept; het verkeerde template
geeft geen harde fout, maar wel rommelige antwoorden. Sommige recente
modellen brengen hun eigen template mee in de GGUF-metadata — in dat
geval moet je géén template forceren.

**mmproj / vision** — sommige modellen kunnen ook afbeeldingen "lezen".
Daarvoor is naast het hoofdmodel een tweede, kleiner bestand nodig
(`mmproj-*.gguf`). Dit bestand hoort bij een specifieke modelversie —
niet uitwisselbaar tussen versies.

**ctx-size / batch-size / ubatch-size** — `--ctx-size` bepaalt hoeveel
tokens (tekst + afbeeldingen samen) het model in één gesprek kan
overzien. `--batch-size` en `--ubatch-size` bepalen hoe die input
intern verwerkt wordt; van de twee blijkt `--ubatch-size` de vlag met
het daadwerkelijke effect op prompt-verwerkingssnelheid, met name bij
afbeeldingen — `--batch-size` alleen heeft daar relatief weinig invloed
op.

## 4. Het taalmodel bijwerken

Zie `/data/scripts/README.md` op de server voor de exacte stappen
(kort samengevat: nieuw modelbestand naar `/data/models/` overzetten,
configuratieblok in `update-model.sh` invullen, script draaien). Het
script maakt automatisch een backup en toont een rollback-commando als
er iets misgaat.

### Wat dit NIET doet

- **De `llama-server`-software zelf vervangen of opnieuw bouwen.** Een
  nieuw model kan een nieuwere llama.cpp-versie vereisen. Je merkt dit
  aan een foutmelding als *"unknown model architecture"* in
  `/var/log/llama-server.log`. Dat oplossen betekent compileren vanaf
  broncode — zie `archief/upgrade-llamacpp.sh` als referentie voor hoe
  dat eerder is aangepakt.
- Wijzigingen aan de webpagina zelf (dat doe je via `jeffrey-v1.0.html`).
- Apache-configuratie.

## 5. Controleren of alles goed werkt

```bash
sudo systemctl status llama-server
tail -f /var/log/llama-server.log
curl -s http://127.0.0.1:8081/health
```

Dat laatste commando zou `{"status":"ok"}` moeten teruggeven.

## 6. Bekend gedrag om rekening mee te houden

- **Het model "hallucineert" soms** — met name bij CVE-nummers geeft
  het model soms een overtuigend klinkend maar **inhoudelijk fout**
  antwoord (bijvoorbeeld de verkeerde softwareleverancier). Gebruik de
  toolkit als hulpmiddel om iets uit te leggen, niet als bron van
  waarheid voor harde feiten — controleer bij twijfel een officiële
  bron zoals nvd.nist.gov.
- **Het model kent geen recente gebeurtenissen** na zijn
  kennis-afkapdatum.
- **Vision-verwerking is CPU-gebonden en traag** — meerdere
  afbeeldingen samen met een document kan enkele minuten duren. Dit
  zit vrijwel volledig in het "lezen" van de afbeeldingen (prompt
  processing), niet in het genereren van het antwoord. Zonder GPU is
  dit inherent aan de architectuur, geen configuratiefout.

## 7. Stand op moment van schrijven (augustus 2026)

Dit is een momentopname — controleer altijd zelf de huidige situatie
(`sudo systemctl status llama-server`, `ls -lh /data/models/`) voordat
je hier iets van aanneemt.

- **Actief model:** Qwen3.6-35B-A3B-MXFP4_MOE (overgestapt vanaf Qwen
  3.5, dezelfde modelfamilie, nieuwere versie).
- **Context:** 32768 tokens (verdubbeld vanaf de oorspronkelijke
  16384), plus `--batch-size 1024` en `--ubatch-size 2048`.
- **Vision:** actief (mmproj, versie-gematcht met het model).
- Rollback naar een eerdere modelversie vereist opnieuw downloaden —
  oude modelbestanden worden na een geslaagde update opgeruimd, niet
  onbeperkt bewaard.
