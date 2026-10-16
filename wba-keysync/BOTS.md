# Bot catalogue

Generated 2026-10-12T12:21:21.812Z by `bun wba-keysync/report.ts wba-keysync/bots.seed.yaml --catalogue --out wba-keysync/BOTS.md`, which fetches every source below. Do not edit it by hand: edit `bots.seed.yaml` and regenerate.

Every source is the bot operator's own (first party). An aggregator may have led us to a bot; it is never the source.

## Reverse DNS

Some operators publish no IP list, only the reverse-DNS names of their crawlers (Baidu, Yandex, Kagi, Scientific Advisor). Checking such a claim takes a DNS lookup and a second lookup to confirm it, so this project does not do it inside a request: it uses each operator's published IP list, compiled when the WAF starts, and Web Bot Auth signatures. Reverse DNS is not built. When it is, it will run offline in the sync tool and be reviewed, never inside a request. This project does not use CRS's fake-bot plugin, which checks reverse DNS while the request waits.

## How to read it

**Level:** the strongest proof the bot supports, strongest first.

| Level | Meaning |
|---|---|
| signature | signs its requests (Web Bot Auth) with keys from its own key directory |
| ip-list | its operator publishes the addresses it sends from |
| rdns | its operator documents the reverse-DNS names of its addresses (this project does not check them yet) |
| user-agent | a token in the User-Agent header |

**Status:** what the check on 2026-10-12 found.

| Status | Meaning |
|---|---|
| verified | its signature keys or IP list were fetched from the operator and are usable |
| documented | reverse DNS only: the operator documents the names; checking them takes a forward-confirmed DNS lookup, which this project does not do yet (planned: offline, never inside a request; see "Reverse DNS" above) |
| claim only | a User-Agent token only, which anyone can send |
| unverified | every source listed failed when checked |

**Category:** a grouping, each defined on the two axes of a Signature Agent Card (draft-meunier-webbotauth-registry-03 3.2.4, 3.2.5): trigger (`crawler` acts on its own, `fetcher` because a user asked) and purpose, from the IETF AIPREF vocabulary (draft-ietf-aipref-vocab-08: `train-ai`, `ai-use`, `search`). AIPREF names AI and search uses only. Why a bot is in its category: the category's meaning, matched to what its operator says it does (quoted under each bot). Two AIPREF readings are still open: whether a page a user named by URL is `ai-use` (vocab-08 4.2, issue 249), and whether an AI search index is `search` (4.3 excludes generated summaries). The labels below are the likelier reading.

| Category | Trigger | AIPREF purpose | Meaning | Bots |
|---|---|---|---|---|
| search | crawler | search | Crawls to build a search index that sends users to the pages it lists | 15 |
| training | crawler | train-ai | Crawls to collect content for training AI models | 5 |
| ai-search | crawler | ai-use, search | Crawls to build an index that an AI assistant answers from | 10 |
| user-fetch | fetcher | ai-use | Fetches a page because a user asked an AI assistant to | 7 |
| agent | fetcher | ai-use | A hosted browser or agent acting for a user, from its operator's servers | 3 |
| local-agent | fetcher | ai-use | An AI tool on the user's own machine, sending from the user's own address | 2 |
| research | crawler | none | Crawls for research, internet measurement or development, not to serve a product | 3 |
| archive | crawler | none | Preserves pages in a public archive | 3 |
| security-scanner | crawler | none | Scans the internet for exposed services or vulnerabilities | 2 |
| seo | crawler | none | Crawls for search-engine optimisation, links or marketing analysis | 4 |
| social-preview | fetcher | none | Fetches a page to show a preview when a user shares its link | 4 |
| monitoring | crawler | none | Checks a site's availability, performance or compliance, usually for its owner | 4 |
| dataset | crawler | none | Crawls to build a dataset it sells or publishes; how buyers use it is theirs to decide | 3 |
| site-service | crawler | none | Fetches for a product the site's owner uses, such as feeds, previews or verification | 3 |
| advertising | crawler | none | Crawls for an advertising product: ad quality, brand safety or ad targeting | 5 |

## Summary

| Bot | Operator | Category | Level | Status |
|---|---|---|---|---|
| [googlebot](#googlebot) | Google | search | ip-list | verified |
| [bingbot](#bingbot) | Microsoft | search | ip-list | verified |
| [applebot](#applebot) | Apple | search | ip-list | verified |
| [duckduckbot](#duckduckbot) | DuckDuckGo | search | ip-list | verified |
| [youbot](#youbot) | You.com | search | signature | verified |
| [gptbot](#gptbot) | OpenAI | training | ip-list | verified |
| [oai-searchbot](#oai-searchbot) | OpenAI | ai-search | ip-list | verified |
| [chatgpt-user](#chatgpt-user) | OpenAI | user-fetch | ip-list | verified |
| [claudebot](#claudebot) | Anthropic | training | ip-list | verified |
| [claude-user](#claude-user) | Anthropic | user-fetch | ip-list | verified |
| [claude-searchbot](#claude-searchbot) | Anthropic | ai-search | ip-list | verified |
| [perplexitybot](#perplexitybot) | Perplexity | ai-search | ip-list | verified |
| [perplexity-user](#perplexity-user) | Perplexity | user-fetch | ip-list | verified |
| [duckassistbot](#duckassistbot) | DuckDuckGo | ai-search | ip-list | verified |
| [mistralai-user](#mistralai-user) | Mistral | user-fetch | ip-list | verified |
| [amazonbot](#amazonbot) | Amazon | training | ip-list | verified |
| [amzn-searchbot](#amzn-searchbot) | Amazon | ai-search | ip-list | verified |
| [amzn-user](#amzn-user) | Amazon | user-fetch | ip-list | verified |
| [bedrockbot](#bedrockbot) | Amazon Web Services | ai-search | user-agent | claim only |
| [ccbot](#ccbot) | Common Crawl | archive | ip-list | verified |
| [chatgpt-agent](#chatgpt-agent) | OpenAI | agent | signature | verified |
| [google-agent](#google-agent) | Google | agent | ip-list | verified |
| [cloudflare-browser-run](#cloudflare-browser-run) | Cloudflare | agent | signature | verified |
| [gemini-cli](#gemini-cli) | Google | local-agent | user-agent | claim only |
| [aider](#aider) | Aider | local-agent | user-agent | claim only |
| [baiduspider](#baiduspider) | Baidu | search | rdns | documented |
| [yandexbot](#yandexbot) | Yandex | search | rdns | documented |
| [naver-yeti](#naver-yeti) | Naver | search | user-agent | claim only |
| [seznambot](#seznambot) | Seznam.cz | search | ip-list | verified |
| [mojeekbot](#mojeekbot) | Mojeek | search | ip-list | verified |
| [kagibot](#kagibot) | Kagi | search | rdns | documented |
| [meta-webindexer](#meta-webindexer) | Meta | ai-search | user-agent | claim only |
| [mistralai-index](#mistralai-index) | Mistral | ai-search | ip-list | verified |
| [meta-externalagent](#meta-externalagent) | Meta | training | user-agent | claim only |
| [ai2bot](#ai2bot) | Allen Institute for AI | training | user-agent | claim only |
| [meta-externalfetcher](#meta-externalfetcher) | Meta | user-fetch | user-agent | claim only |
| [google-user-triggered-fetchers](#google-user-triggered-fetchers) | Google | user-fetch | ip-list | verified |
| [google-special-crawlers](#google-special-crawlers) | Google | site-service | ip-list | verified |
| [archive-org-bot](#archive-org-bot) | Internet Archive | archive | user-agent | claim only |
| [arquivo-web-crawler](#arquivo-web-crawler) | Arquivo.pt \(Portuguese Web Archive\) | archive | user-agent | claim only |
| [icc-crawler](#icc-crawler) | NICT \(Universal Communication Research Institute, Japan\) | research | user-agent | claim only |
| [tno-thesis-crawler](#tno-thesis-crawler) | TNO \(Netherlands\) | research | user-agent | claim only |
| [scientificadvisorbot](#scientificadvisorbot) | Scientific Advisor | dataset | rdns | documented |
| [censysinspect](#censysinspect) | Censys | security-scanner | user-agent | claim only |
| [webzio](#webzio) | Webz.io | dataset | user-agent | claim only |
| [imagesiftbot](#imagesiftbot) | Hive \(Imagesift\) | dataset | user-agent | claim only |
| [ahrefsbot](#ahrefsbot) | Ahrefs | seo | ip-list | verified |
| [semrushbot](#semrushbot) | Semrush | seo | user-agent | claim only |
| [dotbot](#dotbot) | Moz | seo | user-agent | claim only |
| [builtwith](#builtwith) | BuiltWith | seo | user-agent | claim only |
| [uptimerobot](#uptimerobot) | UptimeRobot | monitoring | ip-list | verified |
| [pingdom](#pingdom) | Pingdom \(SolarWinds\) | monitoring | ip-list | verified |
| [betterstack](#betterstack) | Better Stack | monitoring | ip-list | verified |
| [datadog-synthetics](#datadog-synthetics) | Datadog | monitoring | ip-list | verified |
| [facebookexternalhit](#facebookexternalhit) | Meta | social-preview | user-agent | claim only |
| [pinterestbot](#pinterestbot) | Pinterest | social-preview | user-agent | claim only |
| [slackbot](#slackbot) | Slack | social-preview | user-agent | claim only |
| [googleother](#googleother) | Google | research | ip-list | verified |
| [google-cloudvertexbot](#google-cloudvertexbot) | Google | site-service | ip-list | verified |
| [mediapartners-google](#mediapartners-google) | Google | advertising | ip-list | verified |
| [oai-adsbot](#oai-adsbot) | OpenAI | advertising | ip-list | verified |
| [meta-externalads](#meta-externalads) | Meta | advertising | user-agent | claim only |
| [whatsapp-link-preview](#whatsapp-link-preview) | Meta | social-preview | user-agent | claim only |
| [itms](#itms) | Apple | site-service | ip-list | verified |
| [amazonadbot](#amazonadbot) | Amazon Ads | advertising | ip-list | verified |
| [amazon-kendra](#amazon-kendra) | Amazon Web Services | search | user-agent | claim only |
| [amazon-qbusiness](#amazon-qbusiness) | Amazon Web Services | ai-search | user-agent | claim only |
| [amazon-quick](#amazon-quick) | Amazon Web Services | ai-search | user-agent | claim only |
| [aws-security-agent](#aws-security-agent) | Amazon Web Services | security-scanner | user-agent | claim only |
| [adidxbot](#adidxbot) | Microsoft | advertising | user-agent | claim only |
| [bingpreview](#bingpreview) | Microsoft | search | user-agent | claim only |
| [microsoftpreview](#microsoftpreview) | Microsoft | search | user-agent | claim only |
| [bingvideopreview](#bingvideopreview) | Microsoft | search | user-agent | claim only |

## Bots

### search

Crawls to build a search index that sends users to the pages it lists. Trigger `crawler`; AIPREF purpose `search`.

#### googlebot

- **Operator:** Google
- **What its operator says:** "Crawling preferences addressed to the Googlebot user agent affect Google Search \(including Discover and all Google Search features\)"
- **Category:** search
- **Level:** ip-list, rdns, user-agent; **status:** verified (2026-10-12)
- **Sources:**
  - documentation <https://developers.google.com/crawling/docs/crawlers-fetchers/google-common-crawlers>: 200
  - IP list <https://developers.google.com/static/crawling/ipranges/common-crawlers.json>: 317 ranges \(170 IPv4, 147 IPv6\), 2026-10-09T14:46:27.000000
  - reverse DNS googlebot.com: documented; checking needs a forward-confirmed DNS lookup, which this project does not do yet (planned: offline)
  - User-Agent `Googlebot`, `Googlebot-Image`, `Googlebot-Video`, `Storebot-Google`, `Google-InspectionTool`: a claim on its own

#### bingbot

- **Operator:** Microsoft
- **What its operator says:** "Bingbot is our standard crawler and handles most of our crawling needs each day."
- **Note:** Bing's help page is rendered by script; its text is served at https://www.bing.com/webmasters/api/help/htmlcontent?ArticleId=8c184ec0. The 2012 post documents the reverse-DNS check.
- **Category:** search
- **Level:** ip-list, rdns, user-agent; **status:** verified (2026-10-12)
- **Sources:**
  - documentation <https://www.bing.com/webmasters/help/which-crawlers-does-bing-use-8c184ec0>: 200
  - documentation <https://blogs.bing.com/webmaster/2012/8/How-to-Verify-that-Bingbot-is-Bingbot/>: 200
  - IP list <https://www.bing.com/toolbox/bingbot.json>: 28 ranges \(28 IPv4, 0 IPv6\), 2024-01-03T10:00:00.121331
  - reverse DNS search.msn.com: documented; checking needs a forward-confirmed DNS lookup, which this project does not do yet (planned: offline)
  - User-Agent `bingbot`: a claim on its own

#### applebot

- **Operator:** Apple
- **What its operator says:** "The data crawled by Applebot is used to power various features, such as the search technology integrated into many..."
- **Category:** search
- **Level:** ip-list, rdns, user-agent; **status:** verified (2026-10-12)
- **Sources:**
  - documentation <https://support.apple.com/en-us/119829>: 200
  - IP list <https://search.developer.apple.com/applebot.json>: 24 ranges \(24 IPv4, 0 IPv6\), 2026-09-15T10:00:00.000000
  - reverse DNS applebot.apple.com: documented; checking needs a forward-confirmed DNS lookup, which this project does not do yet (planned: offline)
  - User-Agent `Applebot`: a claim on its own

#### duckduckbot

- **Operator:** DuckDuckGo
- **What its operator says:** "DuckDuckBot’s job is to constantly improve our search results and offer users the best and most secure search experience possible."
- **Category:** search
- **Level:** ip-list, user-agent; **status:** verified (2026-10-12)
- **Sources:**
  - documentation <https://duckduckgo.com/duckduckgo-help-pages/results/duckduckbot>: 200
  - IP list <https://duckduckgo.com/duckduckbot.json>: 486 ranges \(486 IPv4, 0 IPv6\), 2026-09-01T12:44:58.000000
  - User-Agent `DuckDuckBot`: a claim on its own

#### youbot

- **Operator:** You.com
- **What its operator says:** "YouBot is the web crawler that powers the You.com search engine."
- **Category:** search
- **Level:** signature, user-agent; **status:** verified (2026-10-12)
- **Sources:**
  - documentation <https://you.com/docs/youbot>: 200
  - signing keys <https://you.com/.well-known/http-message-signatures-directory>: 1 usable key\(s\); proof invalid \(signature binding0 \(5hbjTA0RjjhxRRquk32fSeRWfTgAdSHCZMK1afI1qvI\): "@authority" cannot be resolved for a directory response\)
  - User-Agent `YouBot`: a claim on its own

#### baiduspider

- **Operator:** Baidu
- **What its operator says:** "We recommend using reverse DNS lookup to verify Baiduspider."
- **Category:** search
- **Level:** rdns, user-agent; **status:** documented (2026-10-12)
- **Sources:**
  - documentation <https://help.baidu.com/question?prod_id=99&class=0&id=3001>: 200
  - reverse DNS baidu.com, baidu.jp: documented; checking needs a forward-confirmed DNS lookup, which this project does not do yet (planned: offline)
  - User-Agent `Baiduspider`, `Baiduspider-image`, `Baiduspider-video`, `Baiduspider-news`, `Baiduspider-favo`: a claim on its own

#### yandexbot

- **Operator:** Yandex
- **What its operator says:** "All Yandex robots have names ending in yandex.ru, yandex.net or yandex.com."
- **Note:** YandexAdditional and YandexAdditionalBot are on the same page with no stated purpose: left out.
- **Category:** search
- **Level:** rdns, user-agent; **status:** documented (2026-10-12)
- **Sources:**
  - documentation <https://yandex.com/support/webmaster/en/robot-workings/check-yandex-robots.html>: 200
  - reverse DNS yandex.ru, yandex.net, yandex.com: documented; checking needs a forward-confirmed DNS lookup, which this project does not do yet (planned: offline)
  - User-Agent `YandexBot`: a claim on its own

#### naver-yeti

- **Operator:** Naver
- **What its operator says:** not recorded
- **Category:** search
- **Level:** user-agent; **status:** claim only (2026-10-12)
- **Sources:**
  - documentation <https://searchadvisor.naver.com/guide/seo-basic-robots>: 200
  - User-Agent `Yeti`: a claim on its own

#### seznambot

- **Operator:** Seznam.cz
- **What its operator says:** "a robot \(also known as web crawler or web spider\) – a program that retrieves content for our search engine"
- **Category:** search
- **Level:** ip-list, rdns, user-agent; **status:** verified (2026-10-12)
- **Sources:**
  - documentation <https://o-seznam.cz/napoveda/vyhledavani/en/seznambot-crawler/>: 200
  - IP list <https://search.seznam.cz/ipranges/seznambot.json>: 92 ranges \(46 IPv4, 46 IPv6\), 2026-07-13T07:56:26.172234
  - reverse DNS seznam.cz: documented; checking needs a forward-confirmed DNS lookup, which this project does not do yet (planned: offline)
  - User-Agent `SeznamBot`: a claim on its own

#### mojeekbot

- **Operator:** Mojeek
- **What its operator says:** "MojeekBot is the web crawler for the Mojeek search engine."
- **Category:** search
- **Level:** ip-list, rdns, user-agent; **status:** verified (2026-10-12)
- **Sources:**
  - documentation <https://www.mojeek.com/bot.html>: 200
  - IP list <https://www.mojeek.com/mojeekbot.json>: 1 ranges \(1 IPv4, 0 IPv6\), 2025-05-14T15:44:06.000000
  - reverse DNS mojeek.com: documented; checking needs a forward-confirmed DNS lookup, which this project does not do yet (planned: offline)
  - User-Agent `MojeekBot`: a claim on its own

#### kagibot

- **Operator:** Kagi
- **What its operator says:** "Kagibot is the web crawler for the Kagi search engine."
- **Note:** Kagi lists its four addresses in its HTML page only, not as a list file.
- **Category:** search
- **Level:** rdns, user-agent; **status:** documented (2026-10-12)
- **Sources:**
  - documentation <https://kagi.com/bot>: 200
  - reverse DNS kagibot.org: documented; checking needs a forward-confirmed DNS lookup, which this project does not do yet (planned: offline)
  - User-Agent `Kagibot`: a claim on its own

#### amazon-kendra

- **Operator:** Amazon Web Services
- **What its operator says:** "Amazon Kendra Web Crawler respects standard robots.txt directives like Allow and Disallow."
- **Note:** Crawls the sites an AWS customer chooses, into that customer's own search index.
- **Category:** search
- **Level:** user-agent; **status:** claim only (2026-10-12)
- **Sources:**
  - documentation <https://docs.aws.amazon.com/kendra/latest/dg/stop-web-crawler.html>: 200
  - User-Agent `amazon-kendra`: a claim on its own

#### bingpreview

- **Operator:** Microsoft
- **What its operator says:** "BingPreview generates page snapshots for Bing."
- **Category:** search
- **Level:** user-agent; **status:** claim only (2026-10-12)
- **Sources:**
  - documentation <https://www.bing.com/webmasters/help/which-crawlers-does-bing-use-8c184ec0>: 200
  - User-Agent `BingPreview`: a claim on its own

#### microsoftpreview

- **Operator:** Microsoft
- **What its operator says:** "MicrosoftPreview generates page snapshots for Microsoft products."
- **Category:** search
- **Level:** user-agent; **status:** claim only (2026-10-12)
- **Sources:**
  - documentation <https://www.bing.com/webmasters/help/which-crawlers-does-bing-use-8c184ec0>: 200
  - User-Agent `MicrosoftPreview`: a claim on its own

#### bingvideopreview

- **Operator:** Microsoft
- **What its operator says:** "BingVideoPreview is a crawler used by Microsoft to provide previews of videos only in Bing."
- **Category:** search
- **Level:** user-agent; **status:** claim only (2026-10-12)
- **Sources:**
  - documentation <https://www.bing.com/webmasters/help/which-crawlers-does-bing-use-8c184ec0>: 200
  - User-Agent `BingVideoPreview`: a claim on its own

### training

Crawls to collect content for training AI models. Trigger `crawler`; AIPREF purpose `train-ai`.

#### gptbot

- **Operator:** OpenAI
- **What its operator says:** "GPTBot is used to make our generative AI foundation models more useful and safe."
- **Category:** training
- **Level:** ip-list, user-agent; **status:** verified (2026-10-12)
- **Sources:**
  - documentation <https://developers.openai.com/api/docs/bots>: 200
  - IP list <https://openai.com/gptbot.json>: 18 ranges \(18 IPv4, 0 IPv6\), 2026-09-22T02:00:07.000000
  - User-Agent `GPTBot`: a claim on its own

#### claudebot

- **Operator:** Anthropic
- **What its operator says:** "ClaudeBot helps enhance the utility and safety of our generative AI models by collecting web content that could potentially contribute to their training."
- **Category:** training
- **Level:** ip-list, user-agent; **status:** verified (2026-10-12)
- **Sources:**
  - documentation <https://support.claude.com/en/articles/8896518-does-anthropic-crawl-data-from-the-web-and-how-can-site-owners-block-the-crawler>: 200
  - IP list <https://claude.com/crawling/bots.json>: 38 ranges \(38 IPv4, 0 IPv6\), 2026-10-07T00:00:00Z
  - User-Agent `ClaudeBot`: a claim on its own

#### amazonbot

- **Operator:** Amazon
- **What its operator says:** "Amazonbot is used to improve our products and services. This helps us provide more accurate information to customers and may be used to train Amazon AI models."
- **Category:** training
- **Level:** ip-list, user-agent; **status:** verified (2026-10-12)
- **Sources:**
  - documentation <https://developer.amazon.com/amazonbot>: 200
  - IP list <https://developer.amazon.com/amazonbot/ip-addresses/>: 1292 ranges \(1292 IPv4, 0 IPv6\), 2026-09-08T05:24:10.610952\+00:00
  - User-Agent `Amazonbot`: a claim on its own

#### meta-externalagent

- **Operator:** Meta
- **What its operator says:** "...crawls the web for use cases such as training foundation AI models or improving products by indexing content directly."
- **Category:** training
- **Level:** user-agent; **status:** claim only (2026-10-12)
- **Sources:**
  - documentation <https://developers.facebook.com/documentation/sharing/webmasters/web-crawlers>: 200
  - User-Agent `meta-externalagent`: a claim on its own

#### ai2bot

- **Operator:** Allen Institute for AI
- **What its operator says:** "The AI2 Bot explores certain domains to find web content. This web content is used to train open language models."
- **Category:** training
- **Level:** user-agent; **status:** claim only (2026-10-12)
- **Sources:**
  - documentation <https://allenai.org/crawler>: 200
  - User-Agent `AI2Bot`: a claim on its own

### ai-search

Crawls to build an index that an AI assistant answers from. Trigger `crawler`; AIPREF purpose `ai-use`, `search`.

#### oai-searchbot

- **Operator:** OpenAI
- **What its operator says:** "OAI-SearchBot is used to surface websites in search results in ChatGPT’s search features."
- **Category:** ai-search
- **Level:** ip-list, user-agent; **status:** verified (2026-10-12)
- **Sources:**
  - documentation <https://developers.openai.com/api/docs/bots>: The operation timed out.
  - IP list <https://openai.com/searchbot.json>: 39 ranges \(39 IPv4, 0 IPv6\), 2026-01-02T11:00:00.000000
  - User-Agent `OAI-SearchBot`: a claim on its own

#### claude-searchbot

- **Operator:** Anthropic
- **What its operator says:** "Claude-SearchBot navigates the web to improve search result quality for users."
- **Category:** ai-search
- **Level:** ip-list, user-agent; **status:** verified (2026-10-12)
- **Sources:**
  - documentation <https://support.claude.com/en/articles/8896518-does-anthropic-crawl-data-from-the-web-and-how-can-site-owners-block-the-crawler>: 200
  - IP list <https://claude.com/crawling/bots.json>: 38 ranges \(38 IPv4, 0 IPv6\), 2026-10-07T00:00:00Z
  - User-Agent `Claude-SearchBot`: a claim on its own

#### perplexitybot

- **Operator:** Perplexity
- **What its operator says:** "PerplexityBot is designed to surface and link websites in search results on Perplexity."
- **Category:** ai-search
- **Level:** ip-list, user-agent; **status:** verified (2026-10-12)
- **Sources:**
  - documentation <https://docs.perplexity.ai/docs/resources/perplexity-crawlers>: 200
  - IP list <https://www.perplexity.ai/perplexitybot.json>: 8 ranges \(8 IPv4, 0 IPv6\), 2025-02-07T16:56:00.000000
  - User-Agent `PerplexityBot`: a claim on its own

#### duckassistbot

- **Operator:** DuckDuckGo
- **What its operator says:** "DuckAssistBot is a web crawler for DuckDuckGo Search that crawls pages in real-time for our AI-assisted answers"
- **Category:** ai-search
- **Level:** ip-list, user-agent; **status:** verified (2026-10-12)
- **Sources:**
  - documentation <https://duckduckgo.com/duckduckgo-help-pages/results/duckassistbot>: 200
  - IP list <https://duckduckgo.com/duckassistbot.json>: 486 ranges \(486 IPv4, 0 IPv6\), 2026-09-01T12:44:58.000000
  - User-Agent `DuckAssistBot`: a claim on its own

#### amzn-searchbot

- **Operator:** Amazon
- **What its operator says:** "Amzn-SearchBot is used to improve search experiences in Amazon products and services."
- **Category:** ai-search
- **Level:** ip-list, user-agent; **status:** verified (2026-10-12)
- **Sources:**
  - documentation <https://developer.amazon.com/amazonbot>: 200
  - IP list <https://developer.amazon.com/amazonbot/searchbot-ip-addresses/>: 816 ranges \(816 IPv4, 0 IPv6\), 2026-09-08T05:24:10.610952\+00:00
  - User-Agent `Amzn-SearchBot`: a claim on its own

#### bedrockbot

- **Operator:** Amazon Web Services
- **What its operator says:** "The Amazon Bedrock provided Web Crawler connects to and crawls URLs you have selected for use in your Amazon Bedrock..."
- **Category:** ai-search
- **Level:** user-agent; **status:** claim only (2026-10-12)
- **Sources:**
  - documentation <https://docs.aws.amazon.com/bedrock/latest/userguide/webcrawl-data-source-connector.html>: 200
  - User-Agent `bedrockbot`: a claim on its own

#### meta-webindexer

- **Operator:** Meta
- **What its operator says:** "...navigates the web to improve Meta AI search result quality for users."
- **Category:** ai-search
- **Level:** user-agent; **status:** claim only (2026-10-12)
- **Sources:**
  - documentation <https://developers.facebook.com/documentation/sharing/webmasters/web-crawlers>: 200
  - User-Agent `meta-webindexer`: a claim on its own

#### mistralai-index

- **Operator:** Mistral
- **What its operator says:** "MistralAI-Index is for automated crawling of the web for indexing purposes only."
- **Category:** ai-search
- **Level:** ip-list, user-agent; **status:** verified (2026-10-12)
- **Sources:**
  - documentation <https://docs.mistral.ai/robots>: 200
  - IP list <https://mistral.ai/mistralai-index-ips.json>: 2 ranges \(2 IPv4, 0 IPv6\), 2026-04-19T12:00:00.000000
  - User-Agent `MistralAI-Index`: a claim on its own

#### amazon-qbusiness

- **Operator:** Amazon Web Services
- **What its operator says:** "Amazon Q Business Web Crawler respects standard robots.txt directives like Allow and Disallow."
- **Note:** Crawls the sites an AWS customer chooses, for that customer's AI assistant. Amazon Q Business is closed to new customers; existing ones keep it.
- **Category:** ai-search
- **Level:** user-agent; **status:** claim only (2026-10-12)
- **Sources:**
  - documentation <https://docs.aws.amazon.com/amazonq/latest/qbusiness-ug/stop-web-crawler.html>: 200
  - User-Agent `amazon-QBusiness`: a claim on its own

#### amazon-quick

- **Operator:** Amazon Web Services
- **What its operator says:** "Web Crawler respects the robots.txt protocol and honors user-agent and allow or disallow directives."
- **Note:** Crawls the sites an AWS customer chooses, for that customer's AI assistant.
- **Category:** ai-search
- **Level:** user-agent; **status:** claim only (2026-10-12)
- **Sources:**
  - documentation <https://docs.aws.amazon.com/quick/latest/userguide/web-crawler-integration.html>: 200
  - User-Agent `amazon-Quick-on-behalf-of-`: a claim on its own

### user-fetch

Fetches a page because a user asked an AI assistant to. Trigger `fetcher`; AIPREF purpose `ai-use`.

#### chatgpt-user

- **Operator:** OpenAI
- **What its operator says:** "When users ask ChatGPT or a CustomGPT a question, it may visit a web page with a ChatGPT-User agent."
- **Category:** user-fetch
- **Level:** ip-list, user-agent; **status:** verified (2026-10-12)
- **Sources:**
  - documentation <https://developers.openai.com/api/docs/bots>: 200
  - IP list <https://openai.com/chatgpt-user.json>: 234 ranges \(234 IPv4, 0 IPv6\), 2026-10-07T16:05:32.418450
  - User-Agent `ChatGPT-User`: a claim on its own

#### claude-user

- **Operator:** Anthropic
- **What its operator says:** "Claude-User supports Claude AI users."
- **Note:** Claude Code's web fetch and the Claude Agent SDK also send "Claude-User \(...\)" from the user's own machine and IP: trust the token only with an address on this list.
- **Category:** user-fetch
- **Level:** ip-list, user-agent; **status:** verified (2026-10-12)
- **Sources:**
  - documentation <https://support.claude.com/en/articles/8896518-does-anthropic-crawl-data-from-the-web-and-how-can-site-owners-block-the-crawler>: 200
  - IP list <https://claude.com/crawling/bots.json>: 38 ranges \(38 IPv4, 0 IPv6\), 2026-10-07T00:00:00Z
  - User-Agent `Claude-User`: a claim on its own

#### perplexity-user

- **Operator:** Perplexity
- **What its operator says:** "Perplexity-User supports user actions within Perplexity."
- **Category:** user-fetch
- **Level:** ip-list, user-agent; **status:** verified (2026-10-12)
- **Sources:**
  - documentation <https://docs.perplexity.ai/docs/resources/perplexity-crawlers>: 200
  - IP list <https://www.perplexity.ai/perplexity-user.json>: 4 ranges \(4 IPv4, 0 IPv6\), 2025-10-17T10:17:00.000000
  - User-Agent `Perplexity-User`: a claim on its own

#### mistralai-user

- **Operator:** Mistral
- **What its operator says:** "MistralAI-User is for user actions in Vibe."
- **Category:** user-fetch
- **Level:** ip-list, user-agent; **status:** verified (2026-10-12)
- **Sources:**
  - documentation <https://docs.mistral.ai/robots>: 200
  - IP list <https://mistral.ai/mistralai-user-ips.json>: 4 ranges \(4 IPv4, 0 IPv6\), 2025-02-19T12:00:00.000000
  - User-Agent `MistralAI-User`: a claim on its own

#### amzn-user

- **Operator:** Amazon
- **What its operator says:** "Amzn-User supports user actions, such as responding to Alexa queries that require up-to-date information."
- **Category:** user-fetch
- **Level:** ip-list, user-agent; **status:** verified (2026-10-12)
- **Sources:**
  - documentation <https://developer.amazon.com/amazonbot>: 200
  - IP list <https://developer.amazon.com/amazonbot/live-ip-addresses/>: 1023 ranges \(1023 IPv4, 0 IPv6\), 2025-11-04T15:57:38.092840\+00:00
  - User-Agent `Amzn-User`: a claim on its own

#### meta-externalfetcher

- **Operator:** Meta
- **What its operator says:** "...fetches individual links at a user's request..."
- **Note:** Meta says this fetcher may bypass robots.txt rules, as user-triggered fetchers do.
- **Category:** user-fetch
- **Level:** user-agent; **status:** claim only (2026-10-12)
- **Sources:**
  - documentation <https://developers.facebook.com/documentation/sharing/webmasters/web-crawlers>: 200
  - User-Agent `meta-externalfetcher`: a claim on its own

#### google-user-triggered-fetchers

- **Operator:** Google
- **What its operator says:** "User-triggered fetchers are initiated by users to perform a fetching function within a Google product."
- **Note:** Google's second list, user-triggered-fetchers.json, resolves to gae.googleusercontent.com: shared Google Cloud customer hosting, so it is left out.
- **Category:** user-fetch
- **Level:** ip-list, rdns, user-agent; **status:** verified (2026-10-12)
- **Sources:**
  - documentation <https://developers.google.com/crawling/docs/crawlers-fetchers/google-user-triggered-fetchers>: 200
  - IP list <https://developers.google.com/static/crawling/ipranges/user-triggered-fetchers-google.json>: 502 ranges \(251 IPv4, 251 IPv6\), 2026-10-09T14:46:27.000000
  - reverse DNS google.com: documented; checking needs a forward-confirmed DNS lookup, which this project does not do yet (planned: offline)
  - User-Agent `Google-Read-Aloud`, `FeedFetcher-Google`, `Google-CWS`, `Google-GeminiNotebook`, `GoogleMessages`, `Google-Pinpoint`, `GoogleProducer`, `Google-Site-Verification`: a claim on its own

### archive

Preserves pages in a public archive. Trigger `crawler`; AIPREF purpose none.

#### ccbot

- **Operator:** Common Crawl
- **What its operator says:** "...producing and maintaining an open repository of web crawl data that is universally accessible and analyzable by anyone."
- **Category:** archive
- **Level:** ip-list, user-agent; **status:** verified (2026-10-12)
- **Sources:**
  - documentation <https://commoncrawl.org/ccbot>: 200
  - IP list <https://index.commoncrawl.org/ccbot.json>: 5 ranges \(4 IPv4, 1 IPv6\), 2026-08-11T13:40:00Z
  - User-Agent `CCBot`: a claim on its own

#### archive-org-bot

- **Operator:** Internet Archive
- **What its operator says:** "The Internet Archive is a nonprofit digital library that preserves web data and makes it available for research purposes"
- **Note:** The item page is rendered by script; the quote is the item's own description \(https://archive.org/metadata/archive.org\_bot\).
- **Category:** archive
- **Level:** user-agent; **status:** claim only (2026-10-12)
- **Sources:**
  - documentation <https://archive.org/details/archive.org_bot>: 200
  - User-Agent `archive.org_bot`, `special_archiver`: a claim on its own

#### arquivo-web-crawler

- **Operator:** Arquivo.pt \(Portuguese Web Archive\)
- **What its operator says:** "Webmasters may detect their servers have been crawled by checking the logs for requests identified by the following user agents"
- **Category:** archive
- **Level:** user-agent; **status:** claim only (2026-10-12)
- **Sources:**
  - documentation <https://sobre.arquivo.pt/en/help/crawling-and-archiving-web-content/>: 200
  - User-Agent `Arquivo-web-crawler`: a claim on its own

### agent

A hosted browser or agent acting for a user, from its operator's servers. Trigger `fetcher`; AIPREF purpose `ai-use`.

#### chatgpt-agent

- **Operator:** OpenAI
- **What its operator says:** not recorded
- **Note:** help.openai.com refuses scripted fetches \(403\): no description recorded.
- **Category:** agent
- **Level:** signature; **status:** verified (2026-10-12)
- **Sources:**
  - documentation <https://help.openai.com/en/articles/11845367-chatgpt-works-cloud-browser-allowlisting>: 200
  - signing keys <https://chatgpt.com/.well-known/http-message-signatures-directory>: 1 usable key\(s\); proof valid

#### google-agent

- **Operator:** Google
- **What its operator says:** "Google-Agent is used by agents hosted on Google infrastructure to navigate the web and perform actions upon user request."
- **Note:** Signs a subset of requests as https://agent.bot.goog \(experimental, per Google\), but its JWK kids and request keyids are labels, not the thumbprints draft -00 5.5 and 5.2 require \(MUST\), so key sync keeps none of its keys. Its alg EdDSA is accepted since 2026-10-09.
- **Category:** agent
- **Level:** ip-list, user-agent; **status:** verified (2026-10-12)
- **Sources:**
  - documentation <https://developers.google.com/crawling/docs/crawlers-fetchers/google-user-triggered-fetchers>: 200
  - documentation <https://developers.google.com/crawling/docs/crawlers-fetchers/web-bot-auth>: 200
  - IP list <https://developers.google.com/static/crawling/ipranges/user-triggered-agents.json>: 20 ranges \(12 IPv4, 8 IPv6\), 2026-10-09T14:47:32.000000
  - User-Agent `Google-Agent`: a claim on its own

#### cloudflare-browser-run

- **Operator:** Cloudflare
- **What its operator says:** "Cloudflare automatically attaches headers to every request made through Browser Run."
- **Category:** agent
- **Level:** signature; **status:** verified (2026-10-12)
- **Sources:**
  - documentation <https://developers.cloudflare.com/browser-run/reference/automatic-request-headers/>: 200
  - signing keys <https://web-bot-auth.cloudflare-browser-rendering-085.workers.dev/.well-known/http-message-signatures-directory>: 3 usable key\(s\); proof invalid \(signature binding0 \(QHrZVI7uYXBXsRaTTUojpmFG0UNelgU8-n5tmuRh08U\): content-digest is not covered \(B.1\); signature binding1 \(3JVD-GUlusv36Msck-1m0nvGAwt3xBNNVIVqYe15CYU\): content-digest is not covered \(B.1\); signature binding2 \(WdHpbKqU\_Xqe-C5zUhXY9yUAuggIzqebBWFV04NEcpc\): content-digest is not covered \(B.1\)\)

### local-agent

An AI tool on the user's own machine, sending from the user's own address. Trigger `fetcher`; AIPREF purpose `ai-use`.

#### gemini-cli

- **Operator:** Google
- **What its operator says:** "The \`web\_fetch\` tool allows the Gemini agent to retrieve and process content from specific URLs provided in your prompt."
- **Category:** local-agent
- **Level:** user-agent; **status:** claim only (2026-10-12)
- **Sources:**
  - documentation <https://github.com/google-gemini/gemini-cli/blob/main/docs/tools/web-fetch.md>: 200
  - documentation <https://github.com/google-gemini/gemini-cli/blob/main/packages/core/src/tools/web-fetch.ts>: 200
  - User-Agent `Google-Gemini-CLI/`: a claim on its own

#### aider

- **Operator:** Aider
- **What its operator says:** "Aider can scrape the text from URLs and add it to the chat."
- **Category:** local-agent
- **Level:** user-agent; **status:** claim only (2026-10-12)
- **Sources:**
  - documentation <https://aider.chat/docs/usage/images-urls.html>: 200
  - documentation <https://github.com/Aider-AI/aider/blob/main/aider/scrape.py>: 200
  - User-Agent `Aider/`: a claim on its own

### site-service

Fetches for a product the site's owner uses, such as feeds, previews or verification. Trigger `crawler`; AIPREF purpose none.

#### google-special-crawlers

- **Operator:** Google
- **What its operator says:** "The special-case crawlers are used by specific Google products where there's an agreement between the crawled site and..."
- **Category:** site-service
- **Level:** ip-list, rdns, user-agent; **status:** verified (2026-10-12)
- **Sources:**
  - documentation <https://developers.google.com/crawling/docs/crawlers-fetchers/google-special-case-crawlers>: 200
  - IP list <https://developers.google.com/static/crawling/ipranges/special-crawlers.json>: 272 ranges \(136 IPv4, 136 IPv6\), 2026-10-09T14:46:28.000000
  - reverse DNS google.com: documented; checking needs a forward-confirmed DNS lookup, which this project does not do yet (planned: offline)
  - User-Agent `AdsBot-Google`, `AdsBot-Google-Mobile`, `APIs-Google`, `Google-Safety`: a claim on its own

#### google-cloudvertexbot

- **Operator:** Google
- **What its operator says:** "...affect crawls requested by the site owners' for building Vertex AI Agents."
- **Category:** site-service
- **Level:** ip-list, rdns, user-agent; **status:** verified (2026-10-12)
- **Sources:**
  - documentation <https://developers.google.com/crawling/docs/crawlers-fetchers/google-common-crawlers>: 200
  - IP list <https://developers.google.com/static/crawling/ipranges/common-crawlers.json>: 317 ranges \(170 IPv4, 147 IPv6\), 2026-10-09T14:46:27.000000
  - reverse DNS googlebot.com: documented; checking needs a forward-confirmed DNS lookup, which this project does not do yet (planned: offline)
  - User-Agent `Google-CloudVertexBot`: a claim on its own

#### itms

- **Operator:** Apple
- **What its operator says:** "The iTMS user agent only crawls URLs associated with registered content on Apple Podcasts."
- **Category:** site-service
- **Level:** ip-list, rdns, user-agent; **status:** verified (2026-10-12)
- **Sources:**
  - documentation <https://support.apple.com/en-us/119829>: 200
  - IP list <https://search.developer.apple.com/applebot.json>: 24 ranges \(24 IPv4, 0 IPv6\), 2026-09-15T10:00:00.000000
  - reverse DNS applebot.apple.com: documented; checking needs a forward-confirmed DNS lookup, which this project does not do yet (planned: offline)
  - User-Agent `iTMS`: a claim on its own

### research

Crawls for research, internet measurement or development, not to serve a product. Trigger `crawler`; AIPREF purpose none.

#### icc-crawler

- **Operator:** NICT \(Universal Communication Research Institute, Japan\)
- **What its operator says:** "a program called a "crawler" that automatically crawls the Internet and collects web pages."
- **Note:** NICT lists its two addresses in its HTML page only, not as a list file.
- **Category:** research
- **Level:** user-agent; **status:** claim only (2026-10-12)
- **Sources:**
  - documentation <https://ucri.nict.go.jp/en/icccrawler.html>: 200
  - User-Agent `ICC-Crawler`: a claim on its own

#### tno-thesis-crawler

- **Operator:** TNO \(Netherlands\)
- **What its operator says:** "automatically collects publicly available university master's theses and related academic documents for research purposes"
- **Category:** research
- **Level:** user-agent; **status:** claim only (2026-10-12)
- **Sources:**
  - documentation <https://diamonds.tno.nl/bot-policy>: 200
  - User-Agent `TNOThesisCrawler`: a claim on its own

#### googleother

- **Operator:** Google
- **What its operator says:** "GoogleOther is the generic crawler that may be used by various product teams for fetching publicly accessible content from sites."
- **Category:** research
- **Level:** ip-list, rdns, user-agent; **status:** verified (2026-10-12)
- **Sources:**
  - documentation <https://developers.google.com/crawling/docs/crawlers-fetchers/google-common-crawlers>: 200
  - IP list <https://developers.google.com/static/crawling/ipranges/common-crawlers.json>: 317 ranges \(170 IPv4, 147 IPv6\), 2026-10-09T14:46:27.000000
  - reverse DNS googlebot.com: documented; checking needs a forward-confirmed DNS lookup, which this project does not do yet (planned: offline)
  - User-Agent `GoogleOther`, `GoogleOther-Image`, `GoogleOther-Video`: a claim on its own

### dataset

Crawls to build a dataset it sells or publishes; how buyers use it is theirs to decide. Trigger `crawler`; AIPREF purpose none.

#### scientificadvisorbot

- **Operator:** Scientific Advisor
- **What its operator says:** "Scientific Advisor helps researchers share and compare real publishing experiences with journals and publishers."
- **Note:** A commercial catalogue, not academic research: its page says it fetches article pages "to read corresponding-author emails already shown on the public article page".
- **Category:** dataset
- **Level:** rdns, user-agent; **status:** documented (2026-10-12)
- **Sources:**
  - documentation <https://scientific-advisor.com/bot>: 200
  - reverse DNS origin.scientific-advisor.com: documented; checking needs a forward-confirmed DNS lookup, which this project does not do yet (planned: offline)
  - User-Agent `ScientificAdvisorBot`: a claim on its own

#### webzio

- **Operator:** Webz.io
- **What its operator says:** "Webzio-extended then goes a step further by tagging the data as usable or not usable for AI/ML training"
- **Category:** dataset
- **Level:** user-agent; **status:** claim only (2026-10-12)
- **Sources:**
  - documentation <https://webz.io/blog/company/from-omgilibot-to-the-webzbot-duo-a-powerful-leap-for-ethical-and-comprehensive-data-collection/>: 200
  - User-Agent `Webzio`, `Webzio-Extended`: a claim on its own

#### imagesiftbot

- **Operator:** Hive \(Imagesift\)
- **What its operator says:** "a web crawler that scrapes the internet for publicly available images to support our suite of web intelligence products"
- **Category:** dataset
- **Level:** user-agent; **status:** claim only (2026-10-12)
- **Sources:**
  - documentation <https://imagesift.com/about>: 200
  - User-Agent `ImagesiftBot`: a claim on its own

### security-scanner

Scans the internet for exposed services or vulnerabilities. Trigger `crawler`; AIPREF purpose none.

#### censysinspect

- **Operator:** Censys
- **What its operator says:** "Censys scans help the scientific community accurately study the Internet."
- **Note:** Censys lists its scanner ranges in its HTML page only, not as a list file.
- **Category:** security-scanner
- **Level:** user-agent; **status:** claim only (2026-10-12)
- **Sources:**
  - documentation <https://docs.censys.com/docs/opt-out-of-data-collection>: 200
  - User-Agent `CensysInspect`: a claim on its own

#### aws-security-agent

- **Operator:** Amazon Web Services
- **What its operator says:** "By default, AWS Security Agent adds a custom header for User-Agent set to securityagent"
- **Note:** A penetration test an AWS customer runs against its own site; the customer may change the User-Agent.
- **Category:** security-scanner
- **Level:** user-agent; **status:** claim only (2026-10-12)
- **Sources:**
  - documentation <https://docs.aws.amazon.com/securityagent/latest/userguide/perform-penetration-test.html>: 200
  - User-Agent `securityagent`: a claim on its own

### seo

Crawls for search-engine optimisation, links or marketing analysis. Trigger `crawler`; AIPREF purpose none.

#### ahrefsbot

- **Operator:** Ahrefs
- **What its operator says:** "Powers the database for both Ahrefs, a marketing intelligence platform, and Yep"
- **Category:** seo
- **Level:** ip-list, rdns, user-agent; **status:** verified (2026-10-12)
- **Sources:**
  - documentation <https://ahrefs.com/robot>: 200
  - IP list <https://api.ahrefs.com/v3/public/crawler-ip-ranges>: 81 ranges \(81 IPv4, 0 IPv6\), no date
  - IP list <https://api.ahrefs.com/v3/public/crawler-ips>: 10350 ranges \(10350 IPv4, 0 IPv6\), no date
  - reverse DNS ahrefs.com, ahrefs.net: documented; checking needs a forward-confirmed DNS lookup, which this project does not do yet (planned: offline)
  - User-Agent `AhrefsBot`, `AhrefsSiteAudit`: a claim on its own

#### semrushbot

- **Operator:** Semrush
- **What its operator says:** "Do not try to block SemrushBot via IP as we do not use any consecutive IP blocks."
- **Category:** seo
- **Level:** user-agent; **status:** claim only (2026-10-12)
- **Sources:**
  - documentation <https://www.semrush.com/bot/>: 200
  - User-Agent `SemrushBot`: a claim on its own

#### dotbot

- **Operator:** Moz
- **What its operator says:** "Dotbot is Moz's web crawler, it gathers web data for the Moz Link Index."
- **Note:** Rogerbot is Moz's separate site-audit crawler.
- **Category:** seo
- **Level:** user-agent; **status:** claim only (2026-10-12)
- **Sources:**
  - documentation <https://moz.com/help/moz-procedures/crawlers/dotbot>: 200
  - User-Agent `DotBot`: a claim on its own

#### builtwith

- **Operator:** BuiltWith
- **What its operator says:** not recorded
- **Category:** seo
- **Level:** user-agent; **status:** claim only (2026-10-12)
- **Sources:**
  - documentation <https://builtwith.com/biup>: 200
  - User-Agent `BuiltWith`: a claim on its own

### monitoring

Checks a site's availability, performance or compliance, usually for its owner. Trigger `crawler`; AIPREF purpose none.

#### uptimerobot

- **Operator:** UptimeRobot
- **What its operator says:** "Download all IPs for allow-listing in .txt, JSON..."
- **Category:** monitoring
- **Level:** ip-list, user-agent; **status:** verified (2026-10-12)
- **Sources:**
  - documentation <https://uptimerobot.com/help/locations/>: 200
  - IP list <https://uptimerobot.com/inc/files/ips/IPv4andIPv6.txt>: 206 ranges \(103 IPv4, 103 IPv6\), Wed, 24 Jun 2026 21:38:57 GMT
  - IP list <https://api.uptimerobot.com/meta/ips>: 206 ranges \(103 IPv4, 103 IPv6\), no date
  - User-Agent `UptimeRobot`: a claim on its own

#### pingdom

- **Operator:** Pingdom \(SolarWinds\)
- **What its operator says:** "The following links provide the probe servers' IP addresses in various formats"
- **Category:** monitoring
- **Level:** ip-list; **status:** verified (2026-10-12)
- **Sources:**
  - documentation <https://documentation.solarwinds.com/en/success_center/pingdom/content/topics/pingdom-probe-servers-ip-addresses.htm>: 200
  - IP list <https://my.pingdom.com/probes/ipv4>: 149 ranges \(149 IPv4, 0 IPv6\), Mon, 12 Oct 2026 11:53:54 GMT
  - IP list <https://my.pingdom.com/probes/ipv6>: 57 ranges \(0 IPv4, 57 IPv6\), Mon, 12 Oct 2026 11:52:31 GMT

#### betterstack

- **Operator:** Better Stack
- **What its operator says:** "Prefer to use User-Agent over IP address allowlisting"
- **Category:** monitoring
- **Level:** ip-list, user-agent; **status:** verified (2026-10-12)
- **Sources:**
  - documentation <https://betterstack.com/docs/uptime/frequently-asked-questions/>: 200
  - IP list <https://incidents.betterstack.com/ips.txt>: 34 ranges \(17 IPv4, 17 IPv6\), no date
  - IP list <https://incidents.betterstack.com/ips-by-cluster.json>: 34 ranges \(17 IPv4, 17 IPv6\), no date
  - User-Agent `Better Stack Better Uptime Bot`: a claim on its own

#### datadog-synthetics

- **Operator:** Datadog
- **What its operator says:** not recorded
- **Category:** monitoring
- **Level:** ip-list; **status:** verified (2026-10-12)
- **Sources:**
  - documentation <https://docs.datadoghq.com/api/latest/ip-ranges/>: 200
  - IP list <https://ip-ranges.datadoghq.com/synthetics.json>: 108 ranges \(107 IPv4, 1 IPv6\), Tue, 25 Aug 2026 19:17:34 GMT

### social-preview

Fetches a page to show a preview when a user shares its link. Trigger `fetcher`; AIPREF purpose none.

#### facebookexternalhit

- **Operator:** Meta
- **What its operator says:** "...crawl the content of an app or website that was shared on one of Meta's family of apps..."
- **Category:** social-preview
- **Level:** user-agent; **status:** claim only (2026-10-12)
- **Sources:**
  - documentation <https://developers.facebook.com/documentation/sharing/webmasters/web-crawlers>: 200
  - User-Agent `facebookexternalhit`: a claim on its own

#### pinterestbot

- **Operator:** Pinterest
- **What its operator says:** "Do not hard code these IP addresses in your site configuration, because the addresses that Pinterestbot uses can change without notice."
- **Category:** social-preview
- **Level:** user-agent; **status:** claim only (2026-10-12)
- **Sources:**
  - documentation <https://help.pinterest.com/en/business/article/pinterestbot>: The operation timed out.
  - User-Agent `Pinterestbot`, `Pinterest`: a claim on its own

#### slackbot

- **Operator:** Slack
- **What its operator says:** "Each robot we use identifies itself uniquely through its user agent."
- **Category:** social-preview
- **Level:** user-agent; **status:** claim only (2026-10-12)
- **Sources:**
  - documentation <https://api.slack.com/robots>: 200
  - User-Agent `Slackbot`, `Slackbot-LinkExpanding`: a claim on its own

#### whatsapp-link-preview

- **Operator:** Meta
- **What its operator says:** "WhatsApp crawls the web page via an HTTP GET request."
- **Category:** social-preview
- **Level:** user-agent; **status:** claim only (2026-10-12)
- **Sources:**
  - documentation <https://developers.facebook.com/documentation/business-messaging/whatsapp/link-previews/>: 200
  - User-Agent `WhatsApp/`: a claim on its own

### advertising

Crawls for an advertising product: ad quality, brand safety or ad targeting. Trigger `crawler`; AIPREF purpose none.

#### mediapartners-google

- **Operator:** Google
- **What its operator says:** "The Mediapartners-Google crawler visits participating sites in order to provide them with relevant ads."
- **Category:** advertising
- **Level:** ip-list, rdns, user-agent; **status:** verified (2026-10-12)
- **Sources:**
  - documentation <https://developers.google.com/crawling/docs/crawlers-fetchers/google-special-case-crawlers>: 200
  - IP list <https://developers.google.com/static/crawling/ipranges/special-crawlers.json>: 272 ranges \(136 IPv4, 136 IPv6\), 2026-10-09T14:46:28.000000
  - reverse DNS google.com: documented; checking needs a forward-confirmed DNS lookup, which this project does not do yet (planned: offline)
  - User-Agent `Mediapartners-Google`: a claim on its own

#### oai-adsbot

- **Operator:** OpenAI
- **What its operator says:** "OAI-AdsBot is used to validate the safety of web pages submitted as ads on ChatGPT."
- **Category:** advertising
- **Level:** ip-list, user-agent; **status:** verified (2026-10-12)
- **Sources:**
  - documentation <https://developers.openai.com/api/docs/bots>: 200
  - IP list <https://openai.com/adsbot.json>: 2 ranges \(2 IPv4, 0 IPv6\), 2026-05-12T03:00:00.000000
  - User-Agent `OAI-AdsBot`: a claim on its own

#### meta-externalads

- **Operator:** Meta
- **What its operator says:** "...crawls the web for use cases such as improving advertising and other business-related products and services."
- **Category:** advertising
- **Level:** user-agent; **status:** claim only (2026-10-12)
- **Sources:**
  - documentation <https://developers.facebook.com/documentation/sharing/webmasters/web-crawlers>: 200
  - User-Agent `meta-externalads`: a claim on its own

#### amazonadbot

- **Operator:** Amazon Ads
- **What its operator says:** "Amazon Ads uses AmazonAdBot to maintain a brand-safe environment for advertisers and deliver more relevant ads to users."
- **Category:** advertising
- **Level:** ip-list, rdns, user-agent; **status:** verified (2026-10-12)
- **Sources:**
  - documentation <https://adbot.amazon.com/>: 200
  - IP list <https://adbot.amazon.com/ip-addresses/>: 50 ranges \(50 IPv4, 0 IPv6\), 2026-01-04T15:00:45.000000\+00:00
  - reverse DNS amazonadbot.com: documented; checking needs a forward-confirmed DNS lookup, which this project does not do yet (planned: offline)
  - User-Agent `AmazonAdBot`: a claim on its own

#### adidxbot

- **Operator:** Microsoft
- **What its operator says:** "AdIdxBot crawls ads and follows the websites from those ads for quality control."
- **Note:** Bing documents its IP list and reverse DNS for Bingbot only, so this entry has neither.
- **Category:** advertising
- **Level:** user-agent; **status:** claim only (2026-10-12)
- **Sources:**
  - documentation <https://www.bing.com/webmasters/help/which-crawlers-does-bing-use-8c184ec0>: 200
  - User-Agent `adidxbot`: a claim on its own
