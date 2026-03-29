package main

import (
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"sync"
	"time"
)

// ── 数据结构 ──────────────────────────────────────────────

// watchvuln-vulninfo
type VulnContent struct {
	UniqueKey    string   `json:"unique_key"`
	Title        string   `json:"title"`
	Description  string   `json:"description"`
	Severity     string   `json:"severity"`
	CVE          string   `json:"cve"`
	Disclosure   string   `json:"disclosure"`
	Solutions    string   `json:"solutions"`
	GithubSearch []string `json:"github_search"`
	References   []string `json:"references"`
	Tags         []string `json:"tags"`
	From         string   `json:"from"`
	Reason       []string `json:"reason"`
}

// watchvuln-initial
type Provider struct {
	Name        string `json:"name"`
	DisplayName string `json:"display_name"`
	Link        string `json:"link"`
}
type InitialContent struct {
	Version        string     `json:"version"`
	VulnCount      int        `json:"vuln_count"`
	Interval       string     `json:"interval"`
	Provider       []Provider `json:"provider"`
	FailedProvider []Provider `json:"failed_provider"`
}

// watchvuln-text
type TextContent struct {
	Message string `json:"message"`
}

// watchvuln 通用消息（type 字段区分）
type WatchvulnMsg struct {
	Type    string          `json:"type"`
	Content json.RawMessage `json:"content"`
}

// POC 情报
type PocItem struct {
	ID    string `json:"id"`
	Title string `json:"title"`
}
type PocSource struct {
	Source    string    `json:"source"`
	Count     int       `json:"count"`
	VulnItems []PocItem `json:"items"`
}
type PocReport struct {
	Time    string      `json:"time"`
	Results []PocSource `json:"results"`
}

// 存储条目
type VulnEntry struct {
	RecvTime string
	Msg      WatchvulnMsg
	// 解析后的具体内容
	VulnContent    *VulnContent
	InitialContent *InitialContent
	TextContent    *TextContent
}

type PocEntry struct {
	RecvTime string
	Report   PocReport
}

// ── 全局存储 ──────────────────────────────────────────────

var (
	mu         sync.RWMutex
	vulnList   []VulnEntry
	pocList    []PocEntry
)

// ── HTML 模板 ─────────────────────────────────────────────

var htmlTmpl = template.Must(template.New("index").Funcs(template.FuncMap{
	"truncateTime": func(s string) string {
		if len(s) > 19 {
			return s[:19]
		}
		return s
	},
	"severityClass": func(s string) string {
		switch s {
		case "严重":
			return "sev-critical"
		case "高危":
			return "sev-high"
		case "中危":
			return "sev-medium"
		case "低危":
			return "sev-low"
		}
		return ""
	},
}).Parse(`<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>漏洞监控</title>
    <style>
        * { box-sizing: border-box; }
        body { font-family: Arial, sans-serif; margin: 0; background: #f0f2f5; }

        /* 顶栏 */
        .topbar {
            background: #1a1a2e; color: white;
            padding: 14px 24px; display: flex; align-items: center; gap: 16px;
        }
        .topbar h1 { margin: 0; font-size: 20px; }
        .topbar .badge {
            background: #e94560; color: white;
            border-radius: 12px; padding: 2px 10px; font-size: 13px;
        }
        .topbar .badge-blue { background: #0f3460; }

        /* 双栏布局 */
        .layout { display: flex; height: calc(100vh - 54px); }
        .panel { flex: 1; overflow-y: auto; padding: 16px; }
        .panel-left { border-right: 2px solid #dde; }
        .panel-title {
            font-size: 15px; font-weight: bold; color: #555;
            margin-bottom: 12px; padding-bottom: 6px;
            border-bottom: 2px solid #e0e0e0;
            display: flex; align-items: center; gap: 8px;
        }
        .panel-title .cnt {
            background: #6c757d; color: white;
            border-radius: 10px; padding: 1px 8px; font-size: 12px;
        }

        /* 通用卡片 */
        .card {
            background: white; border-radius: 8px;
            box-shadow: 0 2px 6px rgba(0,0,0,0.08);
            padding: 16px; margin-bottom: 14px;
        }
        .card-header {
            display: flex; justify-content: space-between;
            align-items: center; margin-bottom: 10px;
        }
        .time { color: #aaa; font-size: 12px; }

        /* 类型标签 */
        .badge-type {
            padding: 3px 10px; border-radius: 4px;
            font-size: 12px; font-weight: bold; color: white;
        }
        .bt-vuln    { background: #e94560; }
        .bt-initial { background: #0f3460; }
        .bt-text    { background: #888; }

        /* 严重程度 */
        .severity {
            display: inline-block; padding: 3px 10px;
            border-radius: 4px; font-size: 12px; font-weight: bold;
        }
        .sev-critical { background: #dc3545; color: white; }
        .sev-high     { background: #fd7e14; color: white; }
        .sev-medium   { background: #ffc107; color: #333; }
        .sev-low      { background: #28a745; color: white; }

        /* 漏洞卡片内容 */
        .vuln-title { font-size: 16px; font-weight: bold; color: #222; margin: 8px 0; }
        .info { margin: 6px 0; line-height: 1.7; font-size: 14px; color: #444; }
        .label { color: #666; font-weight: bold; }
        .tag {
            display: inline-block; background: #e9ecef;
            padding: 2px 8px; border-radius: 3px;
            font-size: 12px; margin: 2px 3px 2px 0;
        }
        .tag-cve { background: #cfe2ff; color: #084298; }
        .links { margin-top: 10px; }
        .links a { color: #007bff; text-decoration: none; margin-right: 12px; font-size: 13px; }
        .links a:hover { text-decoration: underline; }

        /* 系统启动 / 文本消息 */
        .initial-box {
            background: #e8f4fd; border-radius: 6px;
            padding: 12px; font-size: 14px; line-height: 1.8;
        }
        .initial-box a { color: #007bff; text-decoration: none; font-size: 12px; margin-right: 6px; }
        .text-box {
            background: #fff8e1; border-radius: 6px;
            padding: 12px; font-size: 14px;
        }

        /* POC 右侧 */
        .poc-time { color: #aaa; font-size: 12px; margin-bottom: 10px; }
        .source-block { margin-bottom: 14px; }
        .source-name {
            font-weight: bold; font-size: 14px; color: #333;
            display: flex; align-items: center; gap: 8px; margin-bottom: 6px;
        }
        .source-cnt {
            background: #17a2b8; color: white;
            border-radius: 10px; padding: 1px 8px; font-size: 12px;
        }
        .source-cnt-zero { background: #ccc; }
        .poc-item {
            display: flex; align-items: flex-start; gap: 8px;
            padding: 6px 0; border-bottom: 1px solid #f0f0f0;
            font-size: 13px; color: #444;
        }
        .poc-item:last-child { border-bottom: none; }
        .poc-id {
            background: #6c757d; color: white;
            border-radius: 3px; padding: 1px 6px;
            font-size: 11px; white-space: nowrap; margin-top: 2px;
        }
        .no-data { color: #bbb; font-size: 13px; font-style: italic; }
    </style>
</head>
<body>
<div class="topbar">
    <h1>🛡 漏洞监控平台</h1>
    <span class="badge">漏洞推送 {{len .Vulns}}</span>
    <span class="badge badge-blue">POC情报 {{len .Pocs}}</span>
</div>

<div class="layout">
    <!-- 左侧：watchvuln 漏洞推送 -->
    <div class="panel panel-left">
        <div class="panel-title">
            📌 漏洞推送
            <span class="cnt">{{len .Vulns}}</span>
        </div>

        {{range .Vulns}}
        <div class="card">
            {{if eq .Msg.Type "watchvuln-vulninfo"}}
                <div class="card-header">
                    <span class="badge-type bt-vuln">漏洞信息</span>
                    <span class="time">{{.RecvTime}}</span>
                </div>
                {{with .VulnContent}}
                <div class="vuln-title">{{.Title}}</div>
                <div style="margin-bottom:8px;">
                    {{if .Severity}}<span class="severity {{severityClass .Severity}}">{{.Severity}}</span>{{end}}
                    {{if .CVE}}<span class="tag tag-cve">{{.CVE}}</span>{{end}}
                    {{if .Disclosure}}<span class="tag">📅 {{.Disclosure}}</span>{{end}}
                </div>
                {{if .Description}}<div class="info"><span class="label">描述：</span>{{.Description}}</div>{{end}}
                {{if .Solutions}}<div class="info"><span class="label">解决方案：</span><br>{{.Solutions}}</div>{{end}}
                {{if .Tags}}
                <div style="margin:8px 0;">
                    {{range .Tags}}<span class="tag">{{.}}</span>{{end}}
                </div>
                {{end}}
                <div class="links">
                    {{if .From}}<a href="{{.From}}" target="_blank">🔗 来源</a>{{end}}
                    {{range .References}}<a href="{{.}}" target="_blank">📄 参考</a>{{end}}
                    {{range .GithubSearch}}<a href="{{.}}" target="_blank">🐙 GitHub</a>{{end}}
                </div>
                {{end}}

            {{else if eq .Msg.Type "watchvuln-initial"}}
                <div class="card-header">
                    <span class="badge-type bt-initial">系统启动</span>
                    <span class="time">{{.RecvTime}}</span>
                </div>
                {{with .InitialContent}}
                <div class="initial-box">
                    <div>🔖 <strong>版本：</strong>{{.Version}}</div>
                    <div>📦 <strong>已收录漏洞：</strong>{{.VulnCount}} 条</div>
                    <div>⏱ <strong>检查间隔：</strong>{{.Interval}}</div>
                    <div>🌐 <strong>数据源：</strong>
                        {{range .Provider}}<a href="{{.Link}}" target="_blank">{{.DisplayName}}</a>{{end}}
                    </div>
                </div>
                {{end}}

            {{else if eq .Msg.Type "watchvuln-text"}}
                <div class="card-header">
                    <span class="badge-type bt-text">系统消息</span>
                    <span class="time">{{.RecvTime}}</span>
                </div>
                {{with .TextContent}}
                <div class="text-box">{{.Message}}</div>
                {{end}}
            {{end}}
        </div>
        {{end}}
    </div>

    <!-- 右侧：POC / Exploit 情报 -->
    <div class="panel panel-right">
        <div class="panel-title">
            💣 POC / Exploit 情报
            <span class="cnt">{{len .Pocs}}</span>
        </div>

        {{range .Pocs}}
        <div class="card">
            <div class="poc-time">🕐 {{.RecvTime}}（数据时间：{{truncateTime .Report.Time}}）</div>
            {{range .Report.Results}}
            <div class="source-block">
                <div class="source-name">
                    {{.Source}}
                    <span class="source-cnt {{if eq .Count 0}}source-cnt-zero{{end}}">{{.Count}}</span>
                </div>
                {{if .VulnItems}}
                    {{range .VulnItems}}
                    <div class="poc-item">
                        <span class="poc-id">{{.ID}}</span>
                        <span>{{.Title}}</span>
                    </div>
                    {{end}}
                {{else}}
                    <div class="no-data">暂无新增</div>
                {{end}}
            </div>
            {{end}}
        </div>
        {{end}}
    </div>
</div>
</body>
</html>
`))

// ── 页面数据 ──────────────────────────────────────────────

type PageData struct {
	Vulns []VulnEntry
	Pocs  []PocEntry
}

// 反转切片（最新的排在最前）
func reverseVulns(s []VulnEntry) []VulnEntry {
	cp := make([]VulnEntry, len(s))
	copy(cp, s)
	for i, j := 0, len(cp)-1; i < j; i, j = i+1, j-1 {
		cp[i], cp[j] = cp[j], cp[i]
	}
	return cp
}
func reversePocs(s []PocEntry) []PocEntry {
	cp := make([]PocEntry, len(s))
	copy(cp, s)
	for i, j := 0, len(cp)-1; i < j; i, j = i+1, j-1 {
		cp[i], cp[j] = cp[j], cp[i]
	}
	return cp
}

// ── HTTP 处理器 ───────────────────────────────────────────

func indexHandler(w http.ResponseWriter, r *http.Request) {
	mu.RLock()
	data := PageData{
		Vulns: reverseVulns(vulnList),
		Pocs:  reversePocs(pocList),
	}
	mu.RUnlock()

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := htmlTmpl.Execute(w, data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		log.Println("模板渲染错误:", err)
	}
}

func webhookHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	var raw map[string]json.RawMessage
	if err := json.NewDecoder(r.Body).Decode(&raw); err != nil {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		log.Println("JSON 解析错误:", err)
		return
	}

	recvTime := time.Now().Format("2006-01-02 15:04:05")

	// 判断消息类型：有 results 字段 → POC 情报，否则 → watchvuln 推送
	if rawResults, ok := raw["results"]; ok {
		var report PocReport
		// 重新组装完整 JSON
		fullJSON, _ := json.Marshal(raw)
		if err := json.Unmarshal(fullJSON, &report); err != nil {
			http.Error(w, "Bad Request", http.StatusBadRequest)
			log.Println("POC JSON 解析错误:", err)
			return
		}
		_ = rawResults
		entry := PocEntry{RecvTime: recvTime, Report: report}
		mu.Lock()
		pocList = append(pocList, entry)
		mu.Unlock()
		log.Printf("收到POC情报: %d 个来源\n", len(report.Results))
	} else {
		// watchvuln 消息
		var msg WatchvulnMsg
		fullJSON, _ := json.Marshal(raw)
		if err := json.Unmarshal(fullJSON, &msg); err != nil {
			http.Error(w, "Bad Request", http.StatusBadRequest)
			log.Println("Watchvuln JSON 解析错误:", err)
			return
		}
		entry := VulnEntry{RecvTime: recvTime, Msg: msg}
		switch msg.Type {
		case "watchvuln-vulninfo":
			var c VulnContent
			if err := json.Unmarshal(msg.Content, &c); err == nil {
				entry.VulnContent = &c
			}
		case "watchvuln-initial":
			var c InitialContent
			if err := json.Unmarshal(msg.Content, &c); err == nil {
				entry.InitialContent = &c
			}
		case "watchvuln-text":
			var c TextContent
			if err := json.Unmarshal(msg.Content, &c); err == nil {
				entry.TextContent = &c
			}
		}
		mu.Lock()
		vulnList = append(vulnList, entry)
		mu.Unlock()
		log.Printf("收到漏洞信息: type=%s\n", msg.Type)
	}

	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintln(w, `{"status":"ok"}`)
}

// ── 主函数 ────────────────────────────────────────────────

func main() {
	http.HandleFunc("/", indexHandler)
	http.HandleFunc("/webhook", webhookHandler)

	addr := "0.0.0.0:1111"
	log.Printf("🛡 漏洞监控平台启动，监听 http://%s\n", addr)
	if err := http.ListenAndServe(addr, nil); err != nil {
		log.Fatal(err)
	}
}
