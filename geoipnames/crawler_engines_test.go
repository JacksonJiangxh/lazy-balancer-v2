package geoipnames

import "testing"

func TestCrawlerEngines_matchAndVerify(t *testing.T) {
	// Given/When/Then: UA 匹配、PTR 后缀绑定（跨引擎不认）、合法 ID
	cases := []struct {
		ua   string
		want string
	}{
		{"Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)", "googlebot"},
		{"Mozilla/5.0 (compatible; bingbot/2.0)", "bingbot"},
		{"Mozilla/5.0 (compatible; Baiduspider/2.0)", "baiduspider"},
		{"Mozilla/5.0 (compatible; GPTBot/1.0; +https://openai.com/gptbot)", "gptbot"},
		{"Mozilla/5.0 (compatible; DeepSeekBot/1.0)", "deepseekbot"},
		{"Mozilla/5.0 (compatible; Bytespider)", "bytespider"},
		{"Mozilla/5.0 (Macintosh) Chrome/120.0 Safari", ""},
	}
	for _, c := range cases {
		if got := MatchCrawlerEngine(c.ua); got != c.want {
			t.Errorf("MatchCrawlerEngine(%q)=%q, want %q", c.ua, got, c.want)
		}
	}
	// PTR：本引擎后缀认、跨引擎后缀不认（GCP googleusercontent.com 也不认）
	if !CrawlerEnginePTRMatch("googlebot", "crawl-66-249-66-1.googlebot.com") {
		t.Error("googlebot 官方 PTR 应匹配")
	}
	if CrawlerEnginePTRMatch("googlebot", "xx.bc.googleusercontent.com") {
		t.Error("GCP PTR 不应匹配 googlebot（机房伪装墙）")
	}
	if CrawlerEnginePTRMatch("bingbot", "crawl-66-249-66-1.googlebot.com") {
		t.Error("跨引擎 PTR 不应匹配")
	}
	if CrawlerEnginePTRMatch("gptbot", "gpt.example.openai.com.evil.attacker.tld") {
		t.Error("后缀必须锚定在域名尾部")
	}
	if !ValidCrawlerEngineID("gptbot") || ValidCrawlerEngineID("fakebot") {
		t.Error("引擎 ID 校验错误")
	}
}

// Given: 每个引擎一条代表性 UA（含不含 spider/bot 字样的裸标记：DeepSeek/
// 历史修复/历史修复/历史修复/历史修复）与常见非爬虫 UA
// When: 走带合并预筛的 MatchCrawlerEngine
// Then: 每个引擎仍解析为自身 ID、浏览器 UA 为空串，且预筛与无预筛的全表
// 逐条匹配结果完全等价（预筛只是短路，不改变匹配语义）。
func TestCrawlerEnginePrefilter_matchesEveryEngine(t *testing.T) {
	cases := []struct {
		ua   string
		want string
	}{
		{"Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)", "googlebot"},
		{"Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)", "bingbot"},
		{"Mozilla/5.0 (compatible; Baiduspider/2.0; +http://www.baidu.com/search/spider.html)", "baiduspider"},
		{"Sogou web spider/4.0(+http://www.sogou.com/docs/help/webmasters.htm#07)", "sogouspider"},
		{"Sogou inst spider/4.0", "sogouspider"},
		{"Mozilla/5.0 (compatible; 360Spider/1.0)", "so360spider"},
		{"Mozilla/5.0 (compatible; YisouSpider/1.0)", "yisouspider"},
		{"Mozilla/5.0 (compatible; PetalBot/2.0)", "petalbot"},
		{"DuckDuckBot/1.1; (+http://duckduckgo.com/duckduckbot.html)", "duckduckbot"},
		{"DuckDuckGo-Favicons-Bot/1.0", "duckduckbot"},
		{"Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots)", "yandexbot"},
		{"Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko); compatible; GPTBot/1.1; +https://openai.com/gptbot", "gptbot"},
		{"Mozilla/5.0 (compatible; ChatGPT-User/1.0; +https://openai.com/bot)", "gptbot"},
		// 裸 DeepSeek 标记（不含 bot/spider 字样）：字面预筛会漏掉这一形态。
		{"Mozilla/5.0 (compatible; DeepSeek/1.0)", "deepseekbot"},
		{"Mozilla/5.0 (compatible; ClaudeBot/1.0; +claudebot@anthropic.com)", "claudebot"},
		{"Mozilla/5.0 (compatible; Claude-Web/1.0; +claude.ai)", "claudebot"},
		{"Mozilla/5.0 (compatible; anthropic-ai/1.0)", "claudebot"},
		{"Mozilla/5.0 (compatible; PerplexityBot/1.0; +https://perplexity.ai/perplexitybot)", "perplexitybot"},
		{"Mozilla/5.0 (compatible; Perplexity-User/1.0)", "perplexitybot"},
		{"Mozilla/5.0 (compatible; Kimi-SearchBot/1.0)", "kimisearchbot"},
		{"Mozilla/5.0 (compatible; Bytespider; spider-feedback@bytedance.com)", "bytespider"},
		// 大小写不敏感
		{"googlebot/2.1", "googlebot"},
		{"perplexity-user", "perplexitybot"},
		// 普通浏览器/客户端
		{"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36", ""},
		{"Mozilla/5.0 (iPhone; CPU iPhone OS 18_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Mobile/15E148 Safari/604.1", ""},
		{"Mozilla/5.0 (X11; Linux x86_64; rv:133.0) Gecko/20100101 Firefox/133.0", ""},
		{"curl/8.7.1", ""},
		{"", ""},
	}
	covered := make(map[string]bool, len(cases))
	for _, c := range cases {
		if got := MatchCrawlerEngine(c.ua); got != c.want {
			t.Errorf("MatchCrawlerEngine(%q)=%q, want %q", c.ua, got, c.want)
		}
		if c.want != "" {
			covered[c.want] = true
		}
	}

	// 注册表全覆盖：新增引擎必须同时补一条代表性 UA（否则预筛等价性未验证）。
	for i := range crawlerEngines {
		if !covered[crawlerEngines[i].ID] {
			t.Errorf("engine %q has no representative UA case", crawlerEngines[i].ID)
		}
	}

	// 等价性：预筛命中 ⇔ 无预筛的全表逐条匹配命中，且两者选出同一引擎。
	for _, c := range cases {
		want := ""
		for _, e := range crawlerEngines {
			if e.UARegex.MatchString(c.ua) {
				want = e.ID
				break
			}
		}
		if crawlerUAPrefilter.MatchString(c.ua) != (want != "") {
			t.Errorf("prefilter disagreement for UA %q: prefilter=%v sequentialHit=%v",
				c.ua, crawlerUAPrefilter.MatchString(c.ua), want != "")
		}
	}
}
