package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"golang.org/x/net/html"
)

const (
	proxyURL   = "http://127.0.0.1:10808"
	sleepHours = 24

	// Webhook 推送地址，填写你的接收URL，留空则不推送
	webhookURL = "http://127.0.0.1:1111/webhook"
)

var (
	githubToken = "在这里填写你的Token"
	httpClient  *http.Client
)

func init() {
	proxy, _ := url.Parse(proxyURL)
	transport := &http.Transport{Proxy: http.ProxyURL(proxy)}
	httpClient = &http.Client{
		Transport: transport,
		Timeout:   60 * time.Second,
	}
}

func nowStr() string {
	return time.Now().Format("2006-01-02 15:04:05.000000")
}

func utcNow() time.Time {
	return time.Now().UTC()
}

func isoFormat(t time.Time) string {
	return t.Format("2006-01-02T15:04:05Z")
}

// ─── Webhook 数据结构 ─────────────────────────────────────────────────────────

type ResultItem struct {
	ID    string `json:"id"`
	Title string `json:"title"`
}

type CheckResult struct {
	Source string       `json:"source"`
	Count  int          `json:"count"`
	Items  []ResultItem `json:"items"`
}

type Report struct {
	Time    string        `json:"time"`
	Results []CheckResult `json:"results"`
}

func sendWebhook(report Report) {
	if webhookURL == "" {
		return
	}
	body, err := json.Marshal(report)
	if err != nil {
		fmt.Printf("[%s] Webhook 序列化失败: %v\n", nowStr(), err)
		return
	}
	resp, err := httpClient.Post(webhookURL, "application/json", bytes.NewReader(body))
	if err != nil {
		fmt.Printf("[%s] Webhook 发送失败: %v\n", nowStr(), err)
		return
	}
	defer resp.Body.Close()
	fmt.Printf("[%s] Webhook 发送成功: HTTP %d\n", nowStr(), resp.StatusCode)
}

// ─── GitHub API ───────────────────────────────────────────────────────────────

func githubGet(apiURL string, params map[string]string) ([]byte, error) {
	req, err := http.NewRequest("GET", apiURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "WatchPoc/1.0")
	if githubToken != "" {
		req.Header.Set("Authorization", "Bearer "+githubToken)
	}
	q := req.URL.Query()
	for k, v := range params {
		q.Set(k, v)
	}
	req.URL.RawQuery = q.Encode()

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, apiURL)
	}
	return io.ReadAll(resp.Body)
}

func getCommitsByTime(owner, repo, since, until string) ([]map[string]interface{}, error) {
	apiURL := fmt.Sprintf("https://api.github.com/repos/%s/%s/commits", owner, repo)
	body, err := githubGet(apiURL, map[string]string{
		"since":    since,
		"until":    until,
		"per_page": "100",
	})
	if err != nil {
		return nil, err
	}
	var result []map[string]interface{}
	return result, json.Unmarshal(body, &result)
}

func getCommitFiles(owner, repo, sha string) ([]map[string]interface{}, error) {
	apiURL := fmt.Sprintf("https://api.github.com/repos/%s/%s/commits/%s", owner, repo, sha)
	body, err := githubGet(apiURL, nil)
	if err != nil {
		return nil, err
	}
	var result map[string]interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, err
	}
	files, _ := result["files"].([]interface{})
	var out []map[string]interface{}
	for _, f := range files {
		if m, ok := f.(map[string]interface{}); ok {
			out = append(out, m)
		}
	}
	return out, nil
}

func getFileContent(owner, repo, path, ref string) string {
	apiURL := fmt.Sprintf("https://api.github.com/repos/%s/%s/contents/%s", owner, repo, path)
	body, err := githubGet(apiURL, map[string]string{"ref": ref})
	if err != nil {
		return ""
	}
	var result map[string]interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		return ""
	}
	if enc, _ := result["encoding"].(string); enc == "base64" {
		content, _ := result["content"].(string)
		content = strings.ReplaceAll(content, "\n", "")
		decoded, err := base64.StdEncoding.DecodeString(content)
		if err != nil {
			return ""
		}
		return string(decoded)
	}
	return ""
}

// ─── YAML 解析 ────────────────────────────────────────────────────────────────

var (
	reID   = regexp.MustCompile(`(?m)^\s*id\s*:\s*(.+?)\s*$`)
	reName = regexp.MustCompile(`(?m)^\s*name\s*:\s*(.+?)\s*$`)
)

func parseYAMLInfo(text string) (id, name string) {
	if m := reID.FindStringSubmatch(text); len(m) > 1 {
		id = strings.Trim(strings.TrimSpace(m[1]), `"'`)
	}
	if m := reName.FindStringSubmatch(text); len(m) > 1 {
		name = strings.Trim(strings.TrimSpace(m[1]), `"'`)
	}
	return
}

func parseAfrogInfo(text, filename string) (id, name string) {
	if m := reName.FindStringSubmatch(text); len(m) > 1 {
		name = strings.Trim(strings.TrimSpace(m[1]), `"'`)
	}
	base := filepath.Base(filename)
	id = strings.TrimSuffix(base, filepath.Ext(base))
	return
}

// ─── 检查函数 ─────────────────────────────────────────────────────────────────

func checkNuclei() CheckResult {
	result := CheckResult{Source: "Nuclei"}
	owner, repo := "projectdiscovery", "nuclei-templates"
	now := utcNow()
	since := isoFormat(now.Add(-24 * time.Hour))
	until := isoFormat(now)

	commits, err := getCommitsByTime(owner, repo, since, until)
	if err != nil {
		fmt.Printf("Nuclei 检查失败: %v\n", err)
		return result
	}

	type entry struct{ id, name string }
	printed := map[entry]bool{}

	for _, c := range commits {
		sha, _ := c["sha"].(string)
		if sha == "" {
			continue
		}
		files, err := getCommitFiles(owner, repo, sha)
		if err != nil {
			continue
		}
		for _, f := range files {
			status, _ := f["status"].(string)
			filename, _ := f["filename"].(string)
			if status != "added" {
				continue
			}
			if !strings.HasSuffix(filename, ".yaml") && !strings.HasSuffix(filename, ".yml") {
				continue
			}
			content := getFileContent(owner, repo, filename, sha)
			id, name := parseYAMLInfo(content)
			if id != "" && name != "" {
				printed[entry{id, name}] = true
			}
		}
	}

	var entries []entry
	for e := range printed {
		entries = append(entries, e)
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].id < entries[j].id })

	if len(entries) > 0 {
		fmt.Printf("\n[%s] Nuclei 检测到 %d 个更新\n", nowStr(), len(entries))
		for _, e := range entries {
			fmt.Printf("%s - %s\n", e.id, e.name)
			result.Items = append(result.Items, ResultItem{ID: e.id, Title: e.name})
		}
	} else {
		fmt.Printf("[%s] Nuclei 无更新\n", nowStr())
	}
	result.Count = len(result.Items)
	return result
}

func checkAwesome() CheckResult {
	result := CheckResult{Source: "Awesome-POC"}
	owner, repo := "Threekiii", "Awesome-POC"
	now := utcNow()
	since := isoFormat(now.Add(-24 * time.Hour))
	until := isoFormat(now)

	commits, err := getCommitsByTime(owner, repo, since, until)
	if err != nil {
		fmt.Printf("Awesome-POC 检查失败: %v\n", err)
		return result
	}

	changed := map[string]bool{}
	for _, c := range commits {
		sha, _ := c["sha"].(string)
		files, err := getCommitFiles(owner, repo, sha)
		if err != nil {
			continue
		}
		for _, f := range files {
			if status, _ := f["status"].(string); status != "added" {
				continue
			}
			filename, _ := f["filename"].(string)
			base := filepath.Base(filename)
			if strings.HasPrefix(base, "image-") || strings.HasPrefix(strings.ToLower(base), "readme") {
				continue
			}
			nameNoExt := strings.TrimSuffix(base, filepath.Ext(base))
			if nameNoExt != "" {
				changed[nameNoExt] = true
			}
		}
	}

	var keys []string
	for k := range changed {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	if len(keys) > 0 {
		fmt.Printf("\n[%s] Awesome-POC 检测到 %d 个更新\n", nowStr(), len(keys))
		for _, k := range keys {
			fmt.Println(k)
			result.Items = append(result.Items, ResultItem{ID: k, Title: k})
		}
	} else {
		fmt.Printf("[%s] Awesome-POC 无更新\n", nowStr())
	}
	result.Count = len(result.Items)
	return result
}

func checkAfrog() CheckResult {
	result := CheckResult{Source: "Afrog-POCs"}
	owner, repo := "zan8in", "afrog-pocs"
	now := utcNow()
	since := isoFormat(now.Add(-24 * time.Hour))
	until := isoFormat(now)

	commits, err := getCommitsByTime(owner, repo, since, until)
	if err != nil {
		fmt.Printf("Afrog-POCs 检查失败: %v\n", err)
		return result
	}

	type entry struct{ id, name string }
	printed := map[entry]bool{}

	for _, c := range commits {
		sha, _ := c["sha"].(string)
		files, err := getCommitFiles(owner, repo, sha)
		if err != nil {
			continue
		}
		for _, f := range files {
			if status, _ := f["status"].(string); status != "added" {
				continue
			}
			filename, _ := f["filename"].(string)
			if !strings.HasSuffix(filename, ".yaml") && !strings.HasSuffix(filename, ".yml") {
				continue
			}
			content := getFileContent(owner, repo, filename, sha)
			id, name := parseAfrogInfo(content, filename)
			if id != "" && name != "" {
				printed[entry{id, name}] = true
			}
		}
	}

	var entries []entry
	for e := range printed {
		entries = append(entries, e)
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].id < entries[j].id })

	if len(entries) > 0 {
		fmt.Printf("\n[%s] Afrog-POCs 检测到 %d 个更新\n", nowStr(), len(entries))
		for _, e := range entries {
			fmt.Printf("%s - %s\n", e.id, e.name)
			result.Items = append(result.Items, ResultItem{ID: e.id, Title: e.name})
		}
	} else {
		fmt.Printf("[%s] Afrog-POCs 无更新\n", nowStr())
	}
	result.Count = len(result.Items)
	return result
}

func checkEeee() CheckResult {
	result := CheckResult{Source: "eeeeeeeeee-POC"}
	owner, repo := "eeeeeeeeee-code", "POC"
	now := utcNow()
	since := isoFormat(now.Add(-24 * time.Hour))
	until := isoFormat(now)

	commits, err := getCommitsByTime(owner, repo, since, until)
	if err != nil {
		fmt.Printf("eeeeeeeeee-POC 检查失败: %v\n", err)
		return result
	}

	changed := map[string]bool{}
	for _, c := range commits {
		sha, _ := c["sha"].(string)
		files, err := getCommitFiles(owner, repo, sha)
		if err != nil {
			continue
		}
		for _, f := range files {
			if status, _ := f["status"].(string); status != "added" {
				continue
			}
			filename, _ := f["filename"].(string)
			base := filepath.Base(filename)
			if strings.HasPrefix(base, "image-") || strings.HasPrefix(strings.ToLower(base), "readme") {
				continue
			}
			nameNoExt := strings.TrimSuffix(base, filepath.Ext(base))
			if nameNoExt != "" {
				changed[nameNoExt] = true
			}
		}
	}

	var keys []string
	for k := range changed {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	if len(keys) > 0 {
		fmt.Printf("\n[%s] eeeeeeeeee-POC 检测到 %d 个更新\n", nowStr(), len(keys))
		for _, k := range keys {
			fmt.Println(k)
			result.Items = append(result.Items, ResultItem{ID: k, Title: k})
		}
	} else {
		fmt.Printf("[%s] eeeeeeeeee-POC 无更新\n", nowStr())
	}
	result.Count = len(result.Items)
	return result
}

// ─── GitLab API ───────────────────────────────────────────────────────────────

func gitlabGet(apiURL string, params map[string]string) ([]byte, error) {
	req, err := http.NewRequest("GET", apiURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "WatchPoc/1.0")
	q := req.URL.Query()
	for k, v := range params {
		q.Set(k, v)
	}
	req.URL.RawQuery = q.Encode()

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, apiURL)
	}
	return io.ReadAll(resp.Body)
}

var (
	reExploitTitle = regexp.MustCompile(`(?i)\+#\s*Exploit\s+[Tt]itle:\s*(.+)`)
	reTitle        = regexp.MustCompile(`(?i)\+#\s*[Tt]itle:\s*(.+)`)
)

func checkExploitDB() CheckResult {
	result := CheckResult{Source: "Exploit-DB"}
	projectID := "exploit-database%2Fexploitdb"
	since := isoFormat(utcNow().Add(-30 * 24 * time.Hour))

	commitsURL := fmt.Sprintf("https://gitlab.com/api/v4/projects/%s/repository/commits", projectID)
	body, err := gitlabGet(commitsURL, map[string]string{"since": since, "per_page": "100"})
	if err != nil {
		fmt.Printf("[%s] Exploit-DB 检查失败: %v\n", nowStr(), err)
		return result
	}

	var commits []map[string]interface{}
	if err := json.Unmarshal(body, &commits); err != nil {
		fmt.Printf("[%s] Exploit-DB 解析失败: %v\n", nowStr(), err)
		return result
	}

	if len(commits) == 0 {
		fmt.Printf("[%s] Exploit-DB 无更新\n", nowStr())
		return result
	}

	type entry struct{ id, title string }
	printed := map[entry]bool{}

	limit := 20
	if len(commits) < limit {
		limit = len(commits)
	}

	for _, commit := range commits[:limit] {
		commitID, _ := commit["id"].(string)
		commitMsg, _ := commit["message"].(string)
		if idx := strings.Index(commitMsg, "\n"); idx >= 0 {
			commitMsg = commitMsg[:idx]
		}
		if commitID == "" {
			continue
		}

		diffURL := fmt.Sprintf("https://gitlab.com/api/v4/projects/%s/repository/commits/%s/diff", projectID, commitID)
		diffBody, err := gitlabGet(diffURL, nil)
		if err != nil {
			continue
		}

		var diffs []map[string]interface{}
		if err := json.Unmarshal(diffBody, &diffs); err != nil {
			continue
		}

		for _, diff := range diffs {
			newFile, _ := diff["new_file"].(bool)
			if !newFile {
				continue
			}
			path, _ := diff["new_path"].(string)
			if !strings.HasPrefix(path, "exploits/") {
				continue
			}

			content, _ := diff["diff"].(string)
			base := filepath.Base(path)
			exploitID := strings.TrimSuffix(base, filepath.Ext(base))

			var title string
			if m := reExploitTitle.FindStringSubmatch(content); len(m) > 1 {
				title = strings.TrimSpace(m[1])
			} else if m := reTitle.FindStringSubmatch(content); len(m) > 1 {
				title = strings.TrimSpace(m[1])
			} else if commitMsg != "" {
				title = commitMsg
			} else {
				title = exploitID
			}

			printed[entry{exploitID, title}] = true
		}
	}

	var entries []entry
	for e := range printed {
		entries = append(entries, e)
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].id < entries[j].id })

	if len(entries) > 0 {
		fmt.Printf("\n[%s] Exploit-DB 检测到 %d 个更新\n", nowStr(), len(entries))
		for _, e := range entries {
			fmt.Printf("%s - %s\n", e.id, e.title)
			result.Items = append(result.Items, ResultItem{ID: e.id, Title: e.title})
		}
	} else {
		fmt.Printf("[%s] Exploit-DB 无更新\n", nowStr())
	}
	result.Count = len(result.Items)
	return result
}

// ─── ExpKu HTML 解析 ──────────────────────────────────────────────────────────

func getText(n *html.Node) string {
	if n.Type == html.TextNode {
		return n.Data
	}
	var sb strings.Builder
	for c := n.FirstChild; c != nil; c = c.NextSibling {
		sb.WriteString(getText(c))
	}
	return strings.TrimSpace(sb.String())
}

func hasClass(n *html.Node, class string) bool {
	for _, a := range n.Attr {
		if a.Key == "class" {
			for _, c := range strings.Fields(a.Val) {
				if c == class {
					return true
				}
			}
		}
	}
	return false
}

func findAll(n *html.Node, tag, class string) []*html.Node {
	var result []*html.Node
	var walk func(*html.Node)
	walk = func(node *html.Node) {
		if node.Type == html.ElementNode && node.Data == tag && (class == "" || hasClass(node, class)) {
			result = append(result, node)
		}
		for c := node.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(n)
	return result
}

func checkExpKu() CheckResult {
	result := CheckResult{Source: "ExpKu"}
	req, err := http.NewRequest("GET", "https://www.expku.com/", nil)
	if err != nil {
		fmt.Printf("[%s] ExpKu 检查失败: %v\n", nowStr(), err)
		return result
	}
	req.Header.Set("User-Agent", "Mozilla/5.0")

	resp, err := httpClient.Do(req)
	if err != nil {
		fmt.Printf("[%s] ExpKu 检查失败: %v\n", nowStr(), err)
		return result
	}
	defer resp.Body.Close()

	doc, err := html.Parse(resp.Body)
	if err != nil {
		fmt.Printf("[%s] ExpKu 解析失败: %v\n", nowStr(), err)
		return result
	}

	cutoff := time.Now().AddDate(0, -1, 0).Format("2006-01-02")
	tables := findAll(doc, "table", "exploit_list")

	type item struct{ date, title string }
	var recent []item

	for _, table := range tables {
		rows := findAll(table, "tr", "")
		if len(rows) <= 1 {
			continue
		}
		for _, row := range rows[1:] {
			cols := findAll(row, "td", "")
			if len(cols) < 3 {
				continue
			}
			date := getText(cols[0])
			title := getText(cols[2])
			if date != "" && title != "" && date >= cutoff {
				recent = append(recent, item{date, title})
			}
		}
	}

	if len(recent) > 0 {
		fmt.Printf("\n[%s] ExpKu 检测到 %d 个近期条目\n", nowStr(), len(recent))
		for _, it := range recent {
			fmt.Printf("%s - %s\n", it.date, it.title)
			result.Items = append(result.Items, ResultItem{ID: it.date, Title: it.title})
		}
	} else {
		fmt.Printf("[%s] ExpKu 无更新\n", nowStr())
	}
	result.Count = len(result.Items)
	return result
}

// ─── 主函数 ───────────────────────────────────────────────────────────────────

func main() {
	fmt.Println("开始监控 nuclei-templates, Awesome-POC, afrog-pocs, eeeeeeeeee-POC, Exploit-DB 和 ExpKu")
	for {
		var results []CheckResult
		results = append(results, checkNuclei())
		results = append(results, checkAwesome())
		results = append(results, checkAfrog())
		results = append(results, checkEeee())
		results = append(results, checkExploitDB())
		results = append(results, checkExpKu())

		report := Report{Time: nowStr(), Results: results}
		sendWebhook(report)

		fmt.Printf("\n[%s] 本轮检查完成，休眠 %d 小时\n\n", nowStr(), sleepHours)
		time.Sleep(sleepHours * time.Hour)
	}
}
