package dashboard

import (
	"bytes"
	"embed"
	"fmt"
	"html/template"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"

	"tinyproxy/internal/dashboard/stats"
	"tinyproxy/internal/server/config"
)

//go:embed templates/*.html
var templateFiles embed.FS

var (
	shellTpl      = template.Must(template.ParseFS(templateFiles, "templates/shell.html"))
	overviewTpl   = template.Must(template.ParseFS(templateFiles, "templates/overview.html"))
	trafficTpl    = template.Must(template.ParseFS(templateFiles, "templates/traffic.html"))
	logsTpl       = template.Must(template.ParseFS(templateFiles, "templates/logs.html"))
	configTpl     = template.Must(template.ParseFS(templateFiles, "templates/config.html"))
	configDiffTpl = template.Must(template.ParseFS(templateFiles, "templates/config_diff.html"))
)

type UIOverviewData struct {
	TotalRequests int64
	ErrorRatePct  float64
	AvgLatencyMs  float64
	BandwidthMB   float64
	SVGPath       template.HTMLAttr
	SVGArea       template.HTMLAttr
}

type UITrafficData struct {
	Window          string
	Windows         []string
	Stats           *stats.StatsResult
	StatusCodesList []StatusCodeEntry
}


type UILogsData struct {
	Level   string
	History []FormattedLog
}

type FormattedLog struct {
	TS      string
	Level   string
	Body    string
}


type StatusCodeEntry struct {
	Code       string
	Count      int64
	ColorClass string
}

// render handles HTMX fragment vs full shell rendering.
func render(w http.ResponseWriter, r *http.Request, tpl *template.Template, activeTab string, data any) {
	if r.Header.Get("HX-Request") == "true" {
		tpl.Execute(w, data)
		return
	}

	var buf bytes.Buffer
	if err := tpl.Execute(&buf, data); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	shellData := struct {
		ActiveTab string
		Content   template.HTML
	}{
		ActiveTab: activeTab,
		Content:   template.HTML(buf.String()),
	}
	shellTpl.Execute(w, shellData)
}

func buildOverviewData(db *stats.DB) (UIOverviewData, error) {
	st, err := db.QueryStats(time.Hour)
	if err != nil {
		return UIOverviewData{}, err
	}

	const (
		width  = 800.0
		height = 200.0
		pad    = 5.0
	)

	var pathBuilder, areaBuilder strings.Builder
	if len(st.RPSSeries) > 0 {
		var maxRPS float64
		for _, p := range st.RPSSeries {
			if p.RPS > maxRPS {
				maxRPS = p.RPS
			}
		}
		if maxRPS == 0 {
			maxRPS = 1.0
		}

		xStep := width / float64(len(st.RPSSeries)-1)
		if len(st.RPSSeries) == 1 {
			xStep = 0
		}

		for i, p := range st.RPSSeries {
			x := float64(i) * xStep
			y := height - pad - (p.RPS/maxRPS)*(height-2*pad)

			if i == 0 {
				fmt.Fprintf(&pathBuilder, "M %.2f %.2f", x, y)
				fmt.Fprintf(&areaBuilder, "M %.2f %.2f", x, height)
				fmt.Fprintf(&areaBuilder, " L %.2f %.2f", x, y)
			} else {
				fmt.Fprintf(&pathBuilder, " L %.2f %.2f", x, y)
				fmt.Fprintf(&areaBuilder, " L %.2f %.2f", x, y)
			}
			if i == len(st.RPSSeries)-1 {
				fmt.Fprintf(&areaBuilder, " L %.2f %.2f", x, height)
				areaBuilder.WriteString(" Z")
			}
		}
	}

	return UIOverviewData{
		TotalRequests: st.TotalRequests,
		ErrorRatePct:  st.ErrorRate * 100,
		AvgLatencyMs:  float64(st.AvgLatencyUS) / 1000.0,
		BandwidthMB:   float64(st.TotalBytes) / 1048576.0,
		SVGPath:       template.HTMLAttr(pathBuilder.String()),
		SVGArea:       template.HTMLAttr(areaBuilder.String()),
	}, nil
}

func RegisterUIHandlers(mux *http.ServeMux, cfgPath string, db *stats.DB, sighupFn func()) {
	// Redirect root to overview
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		http.Redirect(w, r, "/overview", http.StatusTemporaryRedirect)
	})

	mux.HandleFunc("/overview", func(w http.ResponseWriter, r *http.Request) {
		data, err := buildOverviewData(db)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		render(w, r, overviewTpl, "overview", data)
	})

	mux.HandleFunc("/traffic", func(w http.ResponseWriter, r *http.Request) {
		winStr := r.URL.Query().Get("window")
		if winStr == "" {
			winStr = "1h"
		}
		var window time.Duration
		switch winStr {
		case "6h":
			window = 6 * time.Hour
		case "24h":
			window = 24 * time.Hour
		case "7d":
			window = 7 * 24 * time.Hour
		default:
			window = time.Hour
		}

		st, err := db.QueryStats(window)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}

		var scList []StatusCodeEntry
		for code, count := range st.StatusCodes {
			color := "text-green-400"
			if len(code) > 0 {
				if code[0] == '4' {
					color = "text-yellow-400"
				} else if code[0] == '5' {
					color = "text-red-400"
				}
			}
			scList = append(scList, StatusCodeEntry{
				Code: code, Count: count, ColorClass: color,
			})
		}
		sort.Slice(scList, func(i, j int) bool {
			return scList[i].Count > scList[j].Count
		})

		render(w, r, trafficTpl, "traffic", UITrafficData{
			Window:          winStr,
			Windows:         []string{"1h", "6h", "24h", "7d"},
			Stats:           st,
			StatusCodesList: scList,
		})
	})

	mux.HandleFunc("/logs", func(w http.ResponseWriter, r *http.Request) {
		level := r.URL.Query().Get("level")
		history, err := db.QueryLogs(0, 100, "", level)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		
		var formatted []FormattedLog
		for _, l := range history {
			formatted = append(formatted, FormattedLog{
				TS:    time.UnixMilli(l.TS).Format("15:04:05"),
				Level: l.Level,
				Body:  l.Body,
			})
		}

		// history is DESC from DB, so reverse for display (latest at bottom)
		for i, j := 0, len(formatted)-1; i < j; i, j = i+1, j-1 {
			formatted[i], formatted[j] = formatted[j], formatted[i]
		}

		render(w, r, logsTpl, "logs", UILogsData{
			Level:   level,
			History: formatted,
		})
	})

	mux.HandleFunc("/config", func(w http.ResponseWriter, r *http.Request) {
		tab := r.URL.Query().Get("tab")
		if tab == "" {
			tab = "visual"
		}

		raw, err := os.ReadFile(cfgPath)
		if err != nil {
			http.Error(w, "failed to read config: "+err.Error(), 500)
			return
		}
		
		var parsed *config.ServerConfig
		if tab == "visual" {
			parsed, _ = config.NewParser(strings.NewReader(string(raw))).Parse()
		}

		render(w, r, configTpl, "config", map[string]interface{}{
			"Tab":       tab,
			"RawConfig": string(raw),
			"VHosts":    func() map[string]*config.VirtualHost { if parsed != nil { return parsed.VHosts }; return nil }(),
		})
	})

	mux.HandleFunc("/ui/config/validate", func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad request", 400)
			return
		}
		raw := r.FormValue("rawConfig")
		_, parseErr := config.NewParser(strings.NewReader(raw)).Parse()
		
		errMsg := ""
		if parseErr != nil {
			errMsg = parseErr.Error()
		}

		configDiffTpl.Execute(w, map[string]string{
			"RawConfig": raw,
			"Error":     errMsg,
		})
	})

	mux.HandleFunc("/ui/config/save", func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad request", 400)
			return
		}
		raw := r.FormValue("rawConfig")
		if _, parseErr := config.NewParser(strings.NewReader(raw)).Parse(); parseErr != nil {
			http.Error(w, parseErr.Error(), 422)
			return
		}

		tmpPath := cfgPath + ".tmp"
		if err := os.WriteFile(tmpPath, []byte(raw), 0644); err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		if err := os.Rename(tmpPath, cfgPath); err != nil {
			os.Remove(tmpPath)
			http.Error(w, err.Error(), 500)
			return
		}
		
		if sighupFn != nil {
			sighupFn()
		}
		
		w.Header().Set("HX-Redirect", "/config")
	})
}
