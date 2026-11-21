# RASD — Arabic Threat Intelligence: Prior-Work and Gap Survey (raw research notes)

Date of research: 2026-11-21.

## 0. Read this first: evidence tiers and a hard limitation

The research session's network policy blocked direct page fetches for almost every host (arxiv.org, mdpi.com, thesai.org, data.mendeley.com, huggingface.co, kaggle.com, archive.ics.uci.edu, zenodo.org, vendor sites, regulator sites all failed to resolve). Only `github.com` and `raw.githubusercontent.com` could be opened. The strict rule "every claim from a page you actually opened" could therefore be met only for GitHub-hosted sources. Rather than pad the report from memory, every claim below carries one of two tags:

- **[OPENED]** — I fetched and read the page itself (GitHub only).
- **[SNIPPET]** — the claim comes from the search engine's returned excerpt/summary of that URL. The page itself was NOT opened. Treat as a lead to re-verify, not as a verified fact. Numbers in snippets can be wrong or out of date.

Nothing below comes from memory. Where neither tier produced evidence, the item is marked "unverified / not found".

To finish verification, these hosts need to be allowed in the session's network settings: arxiv.org, www.mdpi.com, thesai.org, data.mendeley.com, huggingface.co, www.kaggle.com, archive.ics.uci.edu, zenodo.org, par.nsf.gov, discovery.ucl.ac.uk, cise.ufl.edu, aclanthology.org, sama.gov.sa / rulebook.sama.gov.sa, cst.gov.sa, nca.gov.sa, tra.gov.eg, and the vendor domains listed in Sources.

---

## A. Academic prior work

### A1. Arabic smishing / SMS spam / phishing detection

| Work | Year / venue | Dataset | Method | Reported metrics | Limitations (as far as evidence shows) | Tier |
|---|---|---|---|---|---|---|
| Ghourabi et al., "A Hybrid CNN-LSTM Model for SMS Spam Detection in Arabic and English Messages" (https://doi.org/10.3390/FI12090156) | 2020, Future Internet (MDPI) | 2,730 Arabic messages collected from local smartphones in Saudi Arabia, combined with English messages; public availability not confirmed | CNN-LSTM hybrid | Accuracy reported inconsistently across indexing pages (98.37% vs 96.29%) — conflict unresolved | Per-message binary classification; small Arabic set; no evidence of dialect or campaign analysis | SNIPPET |
| Alsufyani & Alajmani, "A Deep Learning for Arabic SMS Phishing" (https://thesai.org/Downloads/Volume16No1/Paper_38-A_Deep_Learning_for_Arabic_SMS_Phishing.pdf) | 2025, IJACSA Vol. 16 No. 1 (Taif University per snippet) | 16,521 Arabic SMS messages, focused on messages containing URLs; public download not confirmed | CNN, BiGRU, GRU compared; classification driven by URLs in messages | Not captured in snippet | Per-message classification; URL-centric; no campaign linking evidenced | SNIPPET |
| Ibrahim, Alyousef, Alajmi, Aldossari, Masmoudi, "Phishing Detection in Arabic SMS Messages using Natural Language Processing" (https://psau.sa.elsevierpure.com/en/publications/phishing-detection-in-arabic-sms-messages-using-natural-language-/) | 2024, IEEE WiDS-PSU conference | Dataset size/source not found | NLP features + random forest | Acc 98.66%, P 99.10%, R 98.23%, F1 98.67% | Dataset undocumented in what I could see; per-message | SNIPPET |
| "Arabic SMS Spam Detection Using AraBERT and Dual Feature Extraction: A Study on Modern Standard and Iraqi Dialects" (https://sciety.org/articles/activity/10.21203/rs.3.rs-6832100/v1) | Preprint (Research Square), not peer reviewed per snippet | Arabic-translated UCI SMS Spam Collection (MSA) + a new Iraqi-dialect SMS corpus (size not captured) | AraBERT embeddings + CNN-BiLSTM | 99.12% acc (MSA), 95.3% (dialect) | Translated data for MSA; one dialect only; the ~4-point drop on dialect is itself evidence of the dialect gap | SNIPPET |
| Al Saidat, Shaalan, Yerima, "A Novel Approach for Arabic SMS Spam Detection Using Hybrid Deep Learning Techniques" (repo: https://github.com/MohdRasol/A-Novel-Approach-for-Arabic-SMS-Spam-Detection-Using-Hybrid-Deep-Learning-Techniques) | 2024, 6th Int. Conf. on AI in Computational Linguistics (per README BibTeX) | UCI SMS Spam Collection machine-translated to Arabic with ChatGPT-3.5; folders named `ChatGPT_Ham` / `ChatGpt_SPAM` | CNN + Bi-LSTM | Acc 96.99%, P 97.39%, R 96.75%, F1 97.07% | Translated (not native) data; binary ham/spam; no dialects, no indicators, no campaigns | OPENED |
| Alsantali, "A Naive Bayes Classifier for Arabic SMS Spam Messages" (graduation project; https://github.com/KhalidAlsantali/Arabic-SMS-Spam-Data) | Repo updated 2024 | 495 messages, labels 0/1 | Naive Bayes | Not read (paper PDF in repo not opened) | Tiny dataset | OPENED |
| Salloum et al., English/Arabic parallel phishing EMAIL corpus (https://bspace.buid.ac.ae/items/5d77d332-ebfe-451d-81d1-eb58ebf876c0; https://salford-repository.worktribe.com/OutputFile/1744309) | 2023, ACM TALLIP 22(7) | 1,258 emails, built from IWSPA-AP 2018 via translation | TF-IDF + MLP | 96.82% acc on Arabic | Email not SMS; translated; authors state a significant shortage of Arabic phishing corpora | SNIPPET |
| Saudi Digital Library thesis, "Multilingual Model Enhancement Framework for Spam Detection Using a Human-Centred Approach" (https://drepo.sdl.edu.sa/items/f4c778be-dd8f-442b-b88a-ec9fef7f8771) | 2026 per snippet | Multi-stage English-to-Arabic translation pipeline to address dataset scarcity | ML | Not captured | Again translation-based | SNIPPET |
| ASLC-448, Arabic Scam and Legitimate Call Conversation Dataset (https://data.mendeley.com/datasets/p384bgyzz3) | Mendeley Data | 448 annotated conversations, nine Arabic dialects | — | — | Vishing (calls), not text messages; small | SNIPPET |

Cross-cutting observation from a systematic review, "Short Message Service (SMS) Phishing Attacks and Defenses: A Systematic Review" (https://arxiv.org/pdf/2604.11429) [SNIPPET]: it notes Ghourabi et al. used a privately curated Arabic SMS dataset alongside UCI, and that few studies apply SHAP/LIME to smishing.

Pattern across A1 (inference, see section E): every Arabic work found is a per-message classifier; datasets are small, private, or machine-translated; only one preprint touches a single dialect; none links messages into campaigns.

### A2. Dialect identification resources and Arabic pretrained models

- **QADI** (https://github.com/qcri/QADI) [OPENED]: 540,590 tweets from 18 Arab countries, country-level labels; repository ships tweet IDs only (must be hydrated); no license stated on the page.
- **MADAR** [SNIPPET, via https://arxiv.org/pdf/2105.04221 and related]: parallel sentences for 25 cities plus MSA; commissioned (not naturally occurring) text. Country-count figures differ between citing papers — check the original.
- **NADI shared tasks** (2020–2024; e.g. https://arxiv.org/pdf/2310.16117, https://aclanthology.org/2024.arabicnlp-1.79.pdf) [SNIPPET]: country-level (21 countries) and province-level (100 provinces) dialect ID on naturally occurring tweets; NADI 2024 added multi-label dialect ID and "level of dialectness".
- **AraBERT** (https://github.com/aub-mind/arabert) [OPENED]: BERT family from AUB MIND Lab; ~77 GB / ~8.6B words pretraining corpus (mostly MSA news/Wikipedia/OSCAR); AraBERTv0.2-Twitter variants further trained on ~60M multi-dialect tweets with emojis in vocabulary.
- **ARBERT / MARBERT** (https://github.com/UBC-NLP/marbert) [OPENED]: ARBERT is MSA-focused (61 GB, 6.2B tokens); MARBERT is trained on 1B Arabic tweets (128 GB, 15.6B tokens) covering dialectal Arabic and MSA; ~163M parameters. README says checkpoints are "exclusively for research" and commercial use requires contacting the authors — a licensing risk for a startup.
- **CAMeLBERT** (https://raw.githubusercontent.com/CAMeL-Lab/CAMeLBERT/master/README.md) [OPENED]: eight models covering MSA, dialectal Arabic, classical Arabic and a mix; 17.3B tokens total pretraining data. Per-variant sizes (MSA 12.6B, DA 5.8B, CA 864M tokens) are [SNIPPET] only.

None of these resources is trained or evaluated on fraud/smishing text [inference from the above descriptions].

### A3. Campaign clustering / attribution (any language)

- **Nahapetyan et al., "On SMS Phishing Tactics and Infrastructure"** (https://cise.ufl.edu/~k.childs/SMS_Phishing.pdf; https://par.nsf.gov/servlets/purl/10581077) [SNIPPET]: mined 200M+ SMS from 11 public SMS gateways; 67,991 phishing messages grouped into 35,128 campaigns, then clustered into operations; 652 multi-campaign operations; 96% of operations kept the same hostname; infrastructure is often visible in certificate-transparency logs days or weeks before messages are sent. Takeaway: infrastructure (hostnames, certificates) is the stable linking signal and gives lead time.
- **Agarwal, Papasavva, Suarez-Tangil, Vasek, "Fishing for Smishing"** (ACM IMC 2025, DOI 10.1145/3730567.3764431; repo https://github.com/reportsmishing/Smishing-Dataset-IMC25) [OPENED for repo]: mines public user reports; snippet says 64.5k reports from five forums. The released CSV has columns `time, sender_id, telephone_number_type, original_network_name, original_network_country, text, translation, language, url_shortener, named_entity, scam_type, lure_principles`. URLs and phone numbers are masked to `<URL>` / `<PHONE_NUMBER>`; `sender_id` is a category, not the identifier; there is **no campaign/cluster ID column**. The language count file lists 33,788 entries, of which **58 are Arabic** (English 22,078). License CC BY 4.0.
- **Agarwal et al., "An Overview of 7726 User Reports"** (https://arxiv.org/pdf/2508.05276) [SNIPPET]: ~1.35M reports over four months from a major UK operator; 12 scam types; reports are noisy mixtures of spam, scam and legitimate texts.
- **SmishViz** (Sanjari et al.; https://par.nsf.gov/servlets/purl/10620661; https://www.tntech.edu/research/economic-development/techtransfer/story-smishviz.php) [SNIPPET]: clusters messages by template/sentence-embedding similarity first, then connects clusters through shared web infrastructure in tripartite graphs to expose "campaign-operations" possibly run by the same actor. This is the closest academic analogue to RASD's evidence-graph idea; no Arabic focus evidenced.
- **CHURN** (Srinivasan et al., ESORICS 2016; https://astrolavos.gatech.edu/articles/ESORICS16_crosschannel.pdf) [SNIPPET]: hierarchical clustering of SMS-spam domains using network-level, application-level and popularity features; found only ~1% of SMS abuse domains appeared on public domain blacklists.
- **Smishtank dataset paper** (https://arxiv.org/abs/2402.18430) [SNIPPET]: ~1,062–1,090 community-submitted smishing messages (counts differ by version) with sender, body, brand, plus VirusTotal/WHOIS enrichment for URLs.
- **Phishing-kit / email-campaign clustering** [SNIPPET]: kit-family clustering by JavaScript/browser-API usage (https://arxiv.org/html/2509.13186v1, 548 kit families, 4,562 URLs, 97% accuracy); EURECOM multi-criteria email campaign discovery (https://www.eurecom.fr/fr/node/4931709); Unit 42 graph-neural-network pivoting from seed domains, whose authors caution that a single shared link does not prove same-campaign membership (https://unit42.paloaltonetworks.com/graph-neural-networks/).

Text similarity vs infrastructure: the sources above use text templates for grouping messages and infrastructure for linking groups to operators, and at least one warns against single-link attribution. I found no source that directly quantifies text-only clustering failure under paraphrasing — "no public evidence found" in this session.

### A4. Explainability (any language)

- Systematic review (https://arxiv.org/pdf/2604.11429) [SNIPPET]: few studies apply SHAP or LIME to smishing.
- Hybrid CNN-BiGRU smishing detector interpreted with LIME (https://www.mdpi.com/2079-8954/12/11/490) [SNIPPET].
- "ExplainableDetector" transformer SMS spam + explainability (https://arxiv.org/pdf/2405.08026) [SNIPPET, title only].
- SmishX, LLM-agent system generating user-facing explanations (https://par.nsf.gov//servlets/purl/10645870) [SNIPPET].
- Explainable RoBERTa phishing-email model (https://arxiv.org/pdf/2402.13871) [SNIPPET] — English.

All are token/feature attribution or LLM rationales for a single message. I found no work producing evidence-level explanations for a campaign link ("these two messages are linked because they share payee X"), and none for Arabic.

---

## B. Public datasets

### Arabic

| Dataset | URL / download | Size & labels | Real vs synthetic | License | Campaign labels | Tier |
|---|---|---|---|---|---|---|
| Arabic-SMS-Spam-Data (Alsantali) | https://github.com/KhalidAlsantali/Arabic-SMS-Spam-Data ; direct: https://raw.githubusercontent.com/KhalidAlsantali/Arabic-SMS-Spam-Data/main/dataset/Arabic_Spam.csv | README: 495 messages; columns `SMS`, `Sentiment` (0 ham, 1 spam). A downstream repo counted 494 rows / 463 unique after dedup | Provenance not stated. Content read directly: spam is mostly MSA marketing plus fake bank-card-blocked and telco alerts with callback numbers; ham is strongly Saudi/Gulf dialect chat plus transactional notices. URLs (many shorteners) and phone numbers are retained raw, and several spam messages reuse the same callback numbers. Contains credentials/names — must be redacted before reuse | GPL-3.0 | None | OPENED |
| omar-sahhari/arabic-sms-spam-classifier (derived splits) | https://github.com/omar-sahhari/arabic-sms-spam-classifier | 463 unique; 324/69/70 split; TF-IDF char n-gram + LR macro-F1 0.984 vs multilingual-E5 0.924 on 70 test items | Same source as above; README itself flags small size, unaudited template leakage, unmeasured dialect slices | None stated | None | OPENED |
| ChatGPT-translated UCI (Al Saidat et al.) | https://github.com/MohdRasol/A-Novel-Approach-for-Arabic-SMS-Spam-Detection-Using-Hybrid-Deep-Learning-Techniques | Size not stated; ham/spam | Machine-translated from English | GPL-3.0 | None | OPENED |
| Alsufyani & Alajmani Arabic SMS phishing | https://thesai.org/Downloads/Volume16No1/Paper_38-A_Deep_Learning_for_Arabic_SMS_Phishing.pdf | 16,521 messages | Unverified; public availability unverified | Unverified | Unverified | SNIPPET |
| HF repo `Noufy/sms_url_phishing` | https://huggingface.co/Noufy/sms_url_phishing | Tagged Arabic/spam/phishing; contents unverified (possibly related to the row above — unverified) | Unverified | Unverified | Unverified | SNIPPET |
| Ghourabi et al. Saudi SMS | https://doi.org/10.3390/FI12090156 | 2,730 Arabic messages | Real (collected from phones) per snippet; described elsewhere as privately curated | Not public as far as found | None evidenced | SNIPPET |
| Dataset of Arabic Spam and Ham Tweets (Kaddoura & Henno) | https://data.mendeley.com/datasets/86x733xkb8 | v1: 13,241 records; latest version: 11,030 ham / 15,128 spam | Real tweets (Jan–Mar 2021), not SMS | Unverified | None | SNIPPET |
| ASLC-448 | https://data.mendeley.com/datasets/p384bgyzz3 | 448 call conversations, nine dialects | Calls, not messages | Unverified | None | SNIPPET |
| HF `ashu0311/SMS_Spam_Multilingual_Collection_Dataset` | https://huggingface.co/datasets/ashu0311/SMS_Spam_Multilingual_Collection_Dataset | Lists Arabic; ham/spam | Machine-translated from English SMS Spam Collection | Unverified | None | SNIPPET |
| 23-language multilingual spam set (blog post) | https://dev.to/arjun-m/i-built-a-multilingual-spam-detection-dataset-with-149k-messages-across-23-languages-52ac | 149,359 messages incl. Arabic; CC-BY-4.0 per snippet | Blog release; Arabic share and provenance unverified | CC-BY-4.0 (snippet) | None evidenced | SNIPPET |
| Smishing-Dataset-IMC25 (Arabic subset) | https://github.com/reportsmishing/Smishing-Dataset-IMC25 ; direct: https://raw.githubusercontent.com/reportsmishing/Smishing-Dataset-IMC25/main/dataset/final_dataset_output.csv (9 MB) | 58 Arabic entries of 33,788; labels: scam_type, lure_principles, language | Real user reports; indicators masked | CC BY 4.0 | None | OPENED |

Kaggle and Zenodo: no Arabic smishing dataset surfaced in search, and neither site could be opened. "Not found" here is weak evidence, not confirmation of absence.

**Confirmed expectation:** no Arabic dataset found carries campaign-level labels. The only real, native Arabic SMS set I could inspect has under 500 messages.

### Non-Arabic reference sets

- **UCI SMS Spam Collection** (https://archive.ics.uci.edu/ml/datasets/sms+spam+collection) [SNIPPET]: English ham/spam; size and license not verified in this session.
- **Mishra & Soni, SMS Phishing Dataset** (https://data.mendeley.com/datasets/f45bkkt8pr/1; DOI 10.17632/f45bkkt8pr.1) [SNIPPET]: 5,971 messages (4,844 ham, 489 spam, 638 smishing); columns LABEL, TEXT, URL, EMAIL, PHONE where the last three are presence flags; partly produced by OCR of images found online.
- **Balanced spam/smishing set for LLMs** (https://data.mendeley.com/datasets/vmg875v4xs) [SNIPPET]: derived from Mishra & Soni, same schema.
- **Smishtank** (https://arxiv.org/abs/2402.18430) [SNIPPET]: ~1.06–1.09k messages with sender, URL, WHOIS/VirusTotal enrichment — the main set found that retains infrastructure indicators.
- **Smishing-Dataset-IMC25** [OPENED]: see above; indicators masked.
- **shaghayegh-hp/Smishing_Dataset** (https://github.com/shaghayegh-hp/Smishing_Dataset) [OPENED]: merge of five public sets; smishing label assigned by keyword presence (weak labels); academic use only.
- **AbayomiAlli/SMS-Spam-Dataset** (https://github.com/AbayomiAlli/SMS-Spam-Dataset) [SNIPPET]: 5,240 messages (2,350 spam / 2,890 ham).

---

## C. Competitors and existing solutions

### C1. Global

| Vendor / tool | What it does (per source) | Arabic claim | Campaign-level linking | Explanations / API | Tier |
|---|---|---|---|---|---|
| Proofpoint Cloudmark | Operator-side mobile messaging security; 7726 reports feed a "Mobile Abuse Visibility Solution"; ML smishing classifier retrained daily (https://www.cloudmark.com/sites/default/files/data-sheets/cdmk-en-ds-platform-for-mobile-messaging-security.pdf; https://www.proofpoint.com/us/blog/email-and-cloud-threats/us-smishing-increases-reporting-it-just-got-easier) | No language list found | Not evidenced in snippets | Not evidenced | SNIPPET |
| Google Messages Scam Detection | On-device AI warning for SMS/MMS/RCS conversational scams; launched English-only (US/UK/Canada) Mar 2025; a Feb 2026 Google post says 20+ countries and languages "including English, Arabic, French, German, Portuguese, and Spanish" (https://blog.google/security/staying-one-step-ahead-strengthening-androids-lead-in-scam-protection/). A later third-party country list does not match the "20+" figure — conflict | **Arabic claimed** (dialects not specified) | No — per-conversation, on-device | User warning only; no intel API evidenced | SNIPPET |
| Truecaller | Caller ID, spam blocking; AI "Message IDs" for SMS (May 2025, https://www.businesstoday.in/technology/news/story/truecaller-brings-ai-powered-message-ids-for-verified-businesses-and-tackle-sms-spam-475949-2025-05-12); Arabic app UI on Egypt App Store; partnerships with Fawry and Telecom Egypt | UI Arabic; Arabic SMS-fraud model unverified | Not evidenced | Not evidenced | SNIPPET |
| Norton Genie | Scam checker; "designed to work in all languages" but performs best in English, French, German, Japanese, Spanish (https://support.norton.com/sp/en/us/home/current/solutions/v202507031211511) | Arabic not in best-supported list | No | Consumer verdicts | SNIPPET |
| Bitdefender Scamio | AI scam-detection chatbot (https://www.bitdefender.com/news/bitdefender-launches-scamio-a-powerful-scam-detection-service-driven-by-artificial-intelligence.html) | No official Arabic confirmation found; a community thread asks when Arabic will arrive | No | Consumer verdicts | SNIPPET |
| Netcraft | Detection and takedown; phone-scam disruption suspends fraudulent numbers; OCR extracts phone numbers and URLs into threat feeds; vendor-claimed 33-minute median phishing takedown (https://www.netcraft.com/platform/threat-detection-and-takedown/phone-scam-disruption) | Not evidenced | Indicator extraction yes; campaign graph not evidenced | Threat feeds | SNIPPET |
| Group-IB (Digital Risk Protection / Scam Intelligence) | Patented Graph Network Analysis tool maps scam infrastructure; published Arabic-targeting campaigns: PostalFurious, "Venomous Vacancies" (2,400+ fake job pages targeting Arabic speakers in 13 MEA countries), "Hired Hand" (https://www.group-ib.com/media-center/press-releases/venomous-vacancies/; https://www.group-ib.com/media-center/press-releases/postalfurious/) | Tracks Arabic-targeted campaigns; Arabic/dialect NLP not evidenced | **Yes — infrastructure graph** (web/brand focused) | Enterprise platform; self-reported | SNIPPET |
| Resecurity | Threat-intel reporting on Smishing Triad impersonating Emirates Post, with geofenced phishing pages and sends from hijacked iCloud accounts; shared with aeCERT (https://www.resecurity.com/blog/article/Smishing-Triad-Impersonates-Emirates-Post-Target-UAE-Citizens) | Publishes Arabic-language blog pages; product NLP unverified | Analyst-driven actor tracking | Unverified | SNIPPET |
| Recorded Future Brand Intelligence | Typosquat/new-domain monitoring, impersonation monitoring, takedown requests (https://recordedfuture.com/products/brand-intelligence) | Not evidenced | Domain-centric | Not evidenced for this module | SNIPPET |
| Bolster, Memcyco, ZeroFox | Brand-impersonation detection and automated takedown; Memcyco real-time impersonation/ATO protection (https://www.memcyco.com/domain-takedown-services/) | Not evidenced | Not evidenced | Vendor claims only | SNIPPET |
| BioCatch | Behavioural fraud detection for banks; publishes Saudi and UAE fraud surveys (see D) | n/a (behavioural, not text) | n/a | — | SNIPPET |
| ScamAdviser, Feedzai | Searches returned nothing usable | unverified | unverified | unverified | not found |

### C2. Arab region

- **SAMA Joint Operations Center** (https://www.argaam.com/en/article/articledetail/id/1575932; https://saudigazette.com.sa/article/623252) [SNIPPET]: inaugurated July 2022, hosted by Bank Albilad, 24/7 under SAMA supervision, brings all Saudi banks together to handle confirmed fraud cases.
- **SAMA Counter-Fraud Framework** (https://rulebook.sama.gov.sa/en/node/2217) [SNIPPET]: applies to member organisations; calls for sharing confirmed-fraud log-in information (device ID, IP address) through a Sectorial Anti-Fraud Committee; customer awareness is a named element. A SAMA circular (2022) also set daily transfer limits and other measures after a rise in social-engineering fraud (https://english.aawsat.com/home/article/3581946/saudi-arabia-adopts-urgent-measures-combat-financial-fraud).
- **CST (formerly CITC), Saudi Arabia** [SNIPPET]: "Regulations for Curbing SPAM Messages and Calls" (https://www.cst.gov.sa/en/RulesandSystems/RegulatoryDocuments/ReductionofSPAM/Pages/default.aspx); a sender-name management system (https://www.cst.gov.sa/en/media-center/news/To-protect-users-and-enhance-reliability-The-Communications-Authority-launches-a-system-for-managing); a case study claims ~36% reduction in fraud/spam (https://opengov.unescwa.org/node/1230). Aggregator documentation says local SMS must match a registered template, advertising sender names end in "-AD", and operators filter numeric sender IDs and URLs (https://www.infobip.com/docs/essentials/mena-registration/saudi-arabia-letter-of-authorization-loa-guidelines/local-sms-sender-and-template-registration-guideline) — this is vendor documentation, not the regulation text. Reporting short code 330330 reportedly drew nearly one million reports (CST 2019 news).
- **NCA / Haseen** [SNIPPET]: phishing-simulation service for Saudi entities via the Haseen portal (https://nca.gov.sa/en/services/phishing-simulation-service/); **Tahqaq** link/file-checking service for individuals via WhatsApp or Haseen (https://nca.gov.sa/en/news/2093/; https://nca.gov.sa/en/services/tahqaq-for-links/). Tahqaq is a per-link verdict service; no campaign linking is described.
- **UAE** [SNIPPET]: TDRA sender-ID registration and "AD-" prefix for promotional SMS are described by CPaaS vendors only (https://www.twilio.com/en-us/guidelines/ae/sms; https://docs.unifonic.com/docs/uae-sender-id-registration-requirements); effective dates conflict between vendors; the AED 400,000 fine figure is a vendor-blog claim — unverified. UAE Cyber Security Council co-published the 2024 State of Scams in UAE survey (https://www.wam.ae/en/article/b6f93te-2024-state-scams-uae-survey-reveals-65-scam).
- **Egypt NTRA** [SNIPPET]: July 2024 and May/Aug 2025 rules target marketing/spam calls (registration of telemarketing numbers, "NTRA Alert" labels, deactivation of repeat-offender devices; https://www.egypttoday.com/Article/3/140282/NTRA-launches-new-rules-to-regulate-telemarketers-and-spam-calls; https://www.tra.gov.eg/en/ntra-acknowledges-regulations-for-promotional-and-commercial-calls/). No NTRA primary text on SMS sender registration was found.
- **MENA startups** [SNIPPET]: **Rased / Rasēd (Riyadh)** — AI real-time fraud detection startup, pre-seed round led by Wa'ed Ventures and Shorooq Partners, Nov 2025 (https://www.wamda.com/2025/11/rased-raises-pre-seed-round-led-waed-ventures-shorooq-partners). **Name-collision risk with "RASD"**; coverage describes transaction/behaviour fraud detection, not Arabic message analysis. **Mozn (Riyadh)** — FOCAL AML/fraud-prevention platform for financial institutions (https://www.thenationalnews.com/business/start-ups/2023/05/22/generation-start-up-how-mozn-helps-keep-your-money-safe-online-using-ai). No startup doing Arabic-language scam-message or campaign intelligence surfaced.

### C3. Open-source tools and standards

- **MISP** (https://github.com/MISP/MISP) [OPENED]: open-source threat-intel sharing platform; automatic correlation engine; STIX 1/2 export; REST API + PyMISP; AGPL-3.0.
- **OpenCTI** (https://github.com/OpenCTI-Platform/opencti) [OPENED]: STIX 2.1 knowledge-graph platform; connectors, GraphQL API, TAXII 2.1 collections; Community Edition Apache 2.0. Its observable schema defines custom types beyond core STIX, including `Phone-Number`, `Bank-Account`, `Payment-Card`, `Cryptocurrency-Wallet`, `Text`, `Persona` (https://github.com/OpenCTI-Platform/opencti/blob/master/opencti-platform/opencti-graphql/src/schema/stixCyberObservable.ts).
- **STIX 2.1** (https://github.com/oasis-open/cti-stix2-json-schemas) [OPENED]: the observables schema directory lists 18 types (domain-name, url, email-addr, user-account, ...) and shows **no phone-number or bank-account/IBAN observable** in the listing I saw (the page may truncate) — so RASD needs STIX extensions or OpenCTI's custom types for phones and IBANs.
- **TAXII 2.1** (https://docs.oasis-open.org/cti/taxii/v2.1/taxii-v2.1.html) [SNIPPET]: OASIS transport protocol for CTI, standard dated 10 June 2021.
- **URLhaus** (https://urlhaus.abuse.ch/api/) [SNIPPET]: abuse.ch malware-URL sharing with download and authenticated submission API.
- **PhishTank** [SNIPPET, secondary source only]: community phishing-URL feeds; optional app key for higher rate limit.
- **OpenPhish** [SNIPPET, secondary source only]: free community feed updated about every 12 hours with a subset; premium feed is private.

---

## D. Market context (sourced figures only)

| Figure | Source | Year | Caveat | Tier |
|---|---|---|---|---|
| 85% of 100 Saudi bank fraud leaders say fraud attempts are rising; 83% say losses are rising; half estimate annual losses above $10M, 22% above $25M | BioCatch survey (https://www.biocatch.com/press-release/saudi-banking-leaders-overwhelmingly-report-rising-fraud-attempts-and-losses) | 2026 | **Vendor marketing**; perceptions, not audited losses | SNIPPET |
| "Saudi banks report more than 10,000 financial fraud cases in 3 years" | Asharq Al-Awsat headline (https://english.aawsat.com/node/1399431) | period not captured | Headline only | SNIPPET |
| 62% of Saudis exposed to financial-fraud attempts | Saudi Gazette (https://saudigazette.com.sa/article/619840) | 2022 | Survey; sponsor not captured | SNIPPET |
| UAE: ~27% of respondents lost money to a scam, average $2,194; only 9% fully recovered losses; WhatsApp the top scam-delivery platform | GASA / BioCatch State of Scams in UAE 2024 (https://www.biocatch.com/press-release/uae-residents-lose-millions-to-scams-2024) | 2024 | Survey, vendor co-published | SNIPPET |
| 56% of UAE population targeted by a scam attempt at least monthly | UAE Cyber Security Council study reported by Khaleej Times (https://khaleejtimes.com/uae/over-55-of-uae-residents-targeted-by-scams-monthly-shopping-fraud-identity-theft-most-common) | 2024 | Survey | SNIPPET |
| Kaspersky detected 973,061 phishing attacks in Saudi Arabia in Q2 2020 (UAE 617,347) | Gulf Business (https://gulfbusiness.com/en/2020/cybersecurity/saudi-arabia-led-gcc-in-number-of-phishing-attacks-in-q2-kaspersky-report) | 2020 | Vendor telemetry, phishing not smishing, old | SNIPPET |
| 66% of UAE organisations reported at least one smishing attempt in 2022 | Khaleej Times (https://khaleejtimes.com/business/rising-smishing-attacks-raise-concern-among-mobile-users) | 2023 | Original source not identified | SNIPPET |
| "Payment fraud losses hit SAR 1 billion", "AI scams up 300% in 2025" | scamwatchhq.pages.dev | — | **Do not use**: low-quality aggregator, no primary source | SNIPPET |

No official SAMA/SAR total-loss figure and no GASA "State of Scams — Saudi Arabia" report were found. An official headline number for Saudi Arabia is, on this evidence, an open gap in the pitch; do not cite one until the SAMA Financial Stability Report (https://www.sama.gov.sa/en-US/Publications/FinanceReports/Financial%20Stability%20Report/Financial_Stability_Report_2025_En.pdf) or equivalent has actually been read.

---

## E. Synthesis: capability gaps

"Evidence" column is fact (with tier); "Assessment" column is my inference.

| Capability | Evidence found | Assessment (inference) |
|---|---|---|
| Arabic dialect understanding in fraud text | Partially addressed: one preprint on Iraqi dialect with a ~4-point accuracy drop vs MSA [SNIPPET]; Google Messages claims Arabic support, dialects unspecified [SNIPPET]; Norton lists no Arabic among best-supported languages [SNIPPET]. Dialect resources (QADI, MARBERT, CAMeLBERT) exist but are not fraud-specific [OPENED] | Open gap. The one inspectable native dataset shows ham in Gulf dialect and spam in MSA [OPENED], so a classifier can learn "dialect = ham" — a concrete shortcut risk RASD should test for |
| Obfuscation robustness (Arabizi, homoglyphs, dot/diacritic tricks) | Arabic adversarial work exists for bot/offensive-speech detection: Arabizi homograph attack drops F1 0.95 to 0.33 (https://arxiv.org/abs/2402.03171v1) [SNIPPET]; dot-level attacks; Iraqi leetspeak [SNIPPET] | No public evidence found for Arabic smishing specifically |
| Indicator extraction for Arab-specific artifacts (SA/AE/EG phones, IBANs, handles) | Netcraft extracts phone numbers/URLs via OCR [SNIPPET]; Mishra & Soni only flag presence [SNIPPET]; IMC25 masks indicators [OPENED]; STIX 2.1 core listing shows no phone/IBAN observable while OpenCTI adds Phone-Number and Bank-Account [OPENED] | No public evidence found of an Arabic-aware extractor (Eastern Arabic numerals, country formats, IBAN validation). Standards support exists via OpenCTI custom types |
| Campaign linking with evidence standards | Addressed for English/global SMS by Nahapetyan et al., SmishViz, CHURN [SNIPPET]; commercially by Group-IB's graph tool for web infrastructure [SNIPPET]. Unit 42 warns single links are not proof [SNIPPET] | No public evidence found for Arabic message campaigns, nor for an explicit evidence-strength standard for links. No Arabic dataset has campaign labels [OPENED for the sets inspected] — RASD will have to build its own evaluation labels |
| Explainability | LIME/SHAP and LLM rationales per message, English/Bengali/Indonesian [SNIPPET] | No public evidence found for Arabic or for link-level (graph) explanations |
| Privacy | IMC25 demonstrates token masking of URLs/phones/entities [OPENED]; Google's detection is on-device [SNIPPET]; the Alsantali dataset ships raw phones and credentials [OPENED] | Tension: masking destroys the very indicators campaign linking needs. No public evidence found of a privacy-preserving design (e.g. keyed hashing of indicators) for Arabic scam intel |

Bottom line (inference): the defensible gap is not "Arabic spam classification" — several papers report 96–99% on small or translated sets. It is (1) campaign-level linking over Arabic messages with stated evidence standards, (2) Arab-specific indicator extraction, and (3) an evaluation set with campaign labels, which does not publicly exist. The two things most likely to embarrass the pitch are the Rased/Rasēd name collision and the absence of an official Saudi loss figure.

---

## Sources

### Opened and read (GitHub)
- https://github.com/aub-mind/arabert
- https://github.com/UBC-NLP/marbert
- https://raw.githubusercontent.com/CAMeL-Lab/CAMeLBERT/master/README.md
- https://github.com/qcri/QADI
- https://github.com/MISP/MISP
- https://github.com/OpenCTI-Platform/opencti
- https://github.com/OpenCTI-Platform/opencti/blob/master/opencti-platform/opencti-graphql/src/schema/stixCyberObservable.ts
- https://github.com/oasis-open/cti-stix2-json-schemas
- https://github.com/oasis-open/cti-stix2-json-schemas/tree/master/schemas/observables
- https://github.com/KhalidAlsantali/Arabic-SMS-Spam-Data
- https://github.com/KhalidAlsantali/Arabic-SMS-Spam-Data/tree/main/dataset
- https://raw.githubusercontent.com/KhalidAlsantali/Arabic-SMS-Spam-Data/main/dataset/Arabic_Spam.csv
- https://github.com/omar-sahhari/arabic-sms-spam-classifier
- https://github.com/MohdRasol/A-Novel-Approach-for-Arabic-SMS-Spam-Detection-Using-Hybrid-Deep-Learning-Techniques
- https://github.com/reportsmishing/Smishing-Dataset-IMC25
- https://raw.githubusercontent.com/reportsmishing/Smishing-Dataset-IMC25/main/code/language_counts.txt
- https://raw.githubusercontent.com/reportsmishing/Smishing-Dataset-IMC25/main/dataset/final_dataset_output.csv (first 100k characters only)
- https://github.com/shaghayegh-hp/Smishing_Dataset
- https://github.com/search?q=arabic+sms+spam&type=repositories
- https://github.com/search?q=smishing+dataset&type=repositories

### Search-result excerpts only (NOT opened; fetch blocked)
- https://thesai.org/Downloads/Volume16No1/Paper_38-A_Deep_Learning_for_Arabic_SMS_Phishing.pdf
- https://doi.org/10.3390/FI12090156
- https://psau.sa.elsevierpure.com/en/publications/phishing-detection-in-arabic-sms-messages-using-natural-language-/
- https://sciety.org/articles/activity/10.21203/rs.3.rs-6832100/v1
- https://drepo.sdl.edu.sa/items/f4c778be-dd8f-442b-b88a-ec9fef7f8771
- https://bspace.buid.ac.ae/items/5d77d332-ebfe-451d-81d1-eb58ebf876c0
- https://salford-repository.worktribe.com/OutputFile/1744309
- https://arxiv.org/pdf/2604.11429
- https://arxiv.org/abs/2402.18430
- https://arxiv.org/pdf/2508.05276
- https://arxiv.org/pdf/2105.04221
- https://arxiv.org/pdf/2310.16117
- https://aclanthology.org/2024.arabicnlp-1.79.pdf
- https://arxiv.org/pdf/2101.01785
- https://arxiv.org/abs/2402.03171v1
- https://arxiv.org/html/2509.13186v1
- https://arxiv.org/pdf/2405.08026
- https://arxiv.org/pdf/2402.13871
- https://www.mdpi.com/2079-8954/12/11/490
- https://cise.ufl.edu/~k.childs/SMS_Phishing.pdf
- https://par.nsf.gov/servlets/purl/10581077
- https://par.nsf.gov/servlets/purl/10620661
- https://par.nsf.gov//servlets/purl/10645870
- https://www.tntech.edu/research/economic-development/techtransfer/story-smishviz.php
- https://discovery.ucl.ac.uk/10214522/1/Agarwal_IMC_2025_Smishing.pdf
- https://astrolavos.gatech.edu/articles/ESORICS16_crosschannel.pdf
- https://www.eurecom.fr/fr/node/4931709
- https://unit42.paloaltonetworks.com/graph-neural-networks/
- https://data.mendeley.com/datasets/p384bgyzz3
- https://data.mendeley.com/datasets/86x733xkb8
- https://data.mendeley.com/datasets/f45bkkt8pr/1
- https://data.mendeley.com/datasets/vmg875v4xs
- https://huggingface.co/Noufy/sms_url_phishing
- https://huggingface.co/datasets/ashu0311/SMS_Spam_Multilingual_Collection_Dataset
- https://dev.to/arjun-m/i-built-a-multilingual-spam-detection-dataset-with-149k-messages-across-23-languages-52ac
- https://github.com/AbayomiAlli/SMS-Spam-Dataset
- https://archive.ics.uci.edu/ml/datasets/sms+spam+collection
- https://www.cloudmark.com/sites/default/files/data-sheets/cdmk-en-ds-platform-for-mobile-messaging-security.pdf
- https://www.proofpoint.com/us/blog/email-and-cloud-threats/us-smishing-increases-reporting-it-just-got-easier
- https://blog.google/security/staying-one-step-ahead-strengthening-androids-lead-in-scam-protection/
- https://blog.google/security/new-ai-powered-scam-detection-features/
- https://www.businesstoday.in/technology/news/story/truecaller-brings-ai-powered-message-ids-for-verified-businesses-and-tackle-sms-spam-475949-2025-05-12
- https://apps.apple.com/eg/app/truecaller/id448142450
- https://support.norton.com/sp/en/us/home/current/solutions/v202507031211511
- https://www.bitdefender.com/news/bitdefender-launches-scamio-a-powerful-scam-detection-service-driven-by-artificial-intelligence.html
- https://community.bitdefender.com/en/discussion/105043/when-will-arabic-be-available-for-your-favorite-bitdefender-products
- https://www.netcraft.com/platform/threat-detection-and-takedown/phone-scam-disruption
- https://www.group-ib.com/media-center/press-releases/venomous-vacancies/
- https://www.group-ib.com/media-center/press-releases/postalfurious/
- https://www.group-ib.com/resources/research-hub/digital-risk-highlights-2025/
- https://www.resecurity.com/blog/article/Smishing-Triad-Impersonates-Emirates-Post-Target-UAE-Citizens
- https://recordedfuture.com/products/brand-intelligence
- https://www.memcyco.com/domain-takedown-services/
- https://www.argaam.com/en/article/articledetail/id/1575932
- https://saudigazette.com.sa/article/623252
- https://rulebook.sama.gov.sa/en/node/2217
- https://www.rulebook.sama.gov.sa/en/node/9663
- https://english.aawsat.com/home/article/3581946/saudi-arabia-adopts-urgent-measures-combat-financial-fraud
- https://english.aawsat.com/node/1399431
- https://www.cst.gov.sa/en/RulesandSystems/RegulatoryDocuments/ReductionofSPAM/Pages/default.aspx
- https://www.cst.gov.sa/en/media-center/news/To-protect-users-and-enhance-reliability-The-Communications-Authority-launches-a-system-for-managing
- https://www.cst.gov.sa/en/services/Spam-Reports
- https://opengov.unescwa.org/node/1230
- https://www.infobip.com/docs/essentials/mena-registration/saudi-arabia-letter-of-authorization-loa-guidelines/local-sms-sender-and-template-registration-guideline
- https://nca.gov.sa/en/services/phishing-simulation-service/
- https://nca.gov.sa/en/news/2093/
- https://nca.gov.sa/en/services/tahqaq-for-links/
- https://www.twilio.com/en-us/guidelines/ae/sms
- https://docs.unifonic.com/docs/uae-sender-id-registration-requirements
- https://www.telerivet.com/blog/uae-sms-compliance-tdra-ad-prefix
- https://www.wam.ae/en/article/b6f93te-2024-state-scams-uae-survey-reveals-65-scam
- https://www.egypttoday.com/Article/3/140282/NTRA-launches-new-rules-to-regulate-telemarketers-and-spam-calls
- https://www.tra.gov.eg/en/ntra-acknowledges-regulations-for-promotional-and-commercial-calls/
- https://www.wamda.com/2025/11/rased-raises-pre-seed-round-led-waed-ventures-shorooq-partners
- https://www.thenationalnews.com/business/start-ups/2023/05/22/generation-start-up-how-mozn-helps-keep-your-money-safe-online-using-ai
- https://docs.oasis-open.org/cti/taxii/v2.1/taxii-v2.1.html
- https://urlhaus.abuse.ch/api/
- https://www.biocatch.com/press-release/saudi-banking-leaders-overwhelmingly-report-rising-fraud-attempts-and-losses
- https://www.biocatch.com/press-release/uae-residents-lose-millions-to-scams-2024
- https://khaleejtimes.com/uae/over-55-of-uae-residents-targeted-by-scams-monthly-shopping-fraud-identity-theft-most-common
- https://khaleejtimes.com/business/rising-smishing-attacks-raise-concern-among-mobile-users
- https://gulfbusiness.com/en/2020/cybersecurity/saudi-arabia-led-gcc-in-number-of-phishing-attacks-in-q2-kaspersky-report
- https://saudigazette.com.sa/article/619840
- https://www.sama.gov.sa/en-US/Publications/FinanceReports/Financial%20Stability%20Report/Financial_Stability_Report_2025_En.pdf (located, not read)
