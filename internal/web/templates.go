// Package web provides the web server and UI for the proxy gateway.
package web

import (
	"embed"
	"html/template"
	"io/fs"
	"reflect"
	"strings"
)

//go:embed embed
var embeddedFiles embed.FS

//go:embed templates
var templatesFiles embed.FS

var templates = make(map[string]*template.Template)
var staticFS fs.FS

// init initializes the templates and static file system.
func init() {
	// Create a sub-filesystem for our static files to remove the 'embed' prefix.
	staticFS, _ = fs.Sub(embeddedFiles, "embed")

	// A replacer for creating safe IDs from names by replacing common invalid characters.
	idReplacer := strings.NewReplacer(" ", "-", ".", "-", "/", "-", "_", "-")

	funcMap := template.FuncMap{
		"join": func(list interface{}, sep string) string {
			s := reflect.ValueOf(list)
			if s.Kind() != reflect.Slice {
				return ""
			}
			var result []string
			for i := 0; i < s.Len(); i++ {
				result = append(result, s.Index(i).String())
			}
			return strings.Join(result, sep)
		},
		"split": func(s, sep string) []string {
			if s == "" {
				return []string{"", ""}
			}
			return strings.Split(s, sep)
		},
		"list": func(items ...interface{}) []interface{} { return items },
		"slice": func(s string, start, end int) string {
			if start < 0 || end > len(s) || start > end {
				return s
			}
			return s[start:end]
		},
		// NEW FUNCTION: Sanitizes a string to be used as a valid HTML ID.
		"safeID": func(s string) string {
			return idReplacer.Replace(s)
		},
	}

	//dashboardTemplate, err := template.New("dashboard.html").Funcs(funcMap).ParseFiles(filepath.Join(templatesDir, "dashboard.html"))
	dashboardTemplate, err := template.New("dashboard.html").Funcs(funcMap).
		ParseFS(templatesFiles, "templates/dashboard.html")
	if err != nil {
		panic(err)
	}
	templates["dashboard"] = dashboardTemplate

	//loginTemplate, err := template.ParseFiles(filepath.Join(templatesDir, "login.html"))
	loginTemplate, err := template.New("login.html").Funcs(funcMap).
		ParseFS(templatesFiles, "templates/login.html")
	if err != nil {
		panic(err)
	}
	templates["login"] = loginTemplate
}

// GetStaticFS returns the embedded filesystem for static assets.
func GetStaticFS() fs.FS {
	return staticFS
}
