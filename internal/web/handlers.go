package web

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/http"
	"proxy-gateway/internal/config"
	"proxy-gateway/internal/manager"
	"strconv"
	"strings"

	"github.com/gorilla/csrf"
	"github.com/rs/zerolog/log"
	"golang.org/x/crypto/argon2"
)

// PageData is a struct to hold all data passed to templates.
type PageData struct {
	CSRFToken string
	Config    *config.Config
}

func httpError(w http.ResponseWriter, msg string, err error, code int) {
	log.Error().Err(err).Msg(msg)
	http.Error(w, msg, code)
}

// --- Page & Global Handlers ---

// LoginPageHandler simply renders the login template.
func LoginPageHandler(w http.ResponseWriter, r *http.Request) {
	if err := templates["login"].Execute(w, nil); err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		log.Printf("template execution error: %v", err)
	}
}

func handleDashboard(cm *manager.ConfigManager, w http.ResponseWriter, r *http.Request) {
	data := PageData{
		CSRFToken: csrf.Token(r),
		Config:    cm.Get(),
	}
	if err := templates["dashboard"].Execute(w, data); err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		log.Printf("template execution error: %v", err)
	}
}

func handleSaveConfig(cm *manager.ConfigManager, w http.ResponseWriter, r *http.Request) {
	if err := cm.SaveToDisk(); err != nil {
		httpError(w, "Failed to save configuration to disk", err, http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// --- Group Handlers ---

func handleAddGroup(cm *manager.ConfigManager, w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/", http.StatusMethodNotAllowed)
		return
	}
	newGroup := config.Group{
		Name:        r.FormValue("name"),
		ClientIPs:   strings.Split(r.FormValue("client_ips"), ","),
		ClientHosts: strings.Split(r.FormValue("client_hosts"), ","),
	}
	cm.Update(func(cfg *config.Config) {
		cfg.Groups = append(cfg.Groups, newGroup)
	})
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func handleUpdateGroup(cm *manager.ConfigManager, w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/", http.StatusMethodNotAllowed)
		return
	}
	originalName := r.FormValue("original_name")
	cm.Update(func(cfg *config.Config) {
		for i := range cfg.Groups {
			if cfg.Groups[i].Name == originalName {
				cfg.Groups[i].Name = r.FormValue("name")
				cfg.Groups[i].ClientIPs = strings.Split(r.FormValue("client_ips"), ",")
				cfg.Groups[i].ClientHosts = strings.Split(r.FormValue("client_hosts"), ",")
				break
			}
		}
	})
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func handleDeleteGroup(cm *manager.ConfigManager, w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/", http.StatusMethodNotAllowed)
		return
	}
	groupName := r.FormValue("name")
	cm.Update(func(cfg *config.Config) {
		var updatedGroups []config.Group
		for _, group := range cfg.Groups {
			if group.Name != groupName {
				updatedGroups = append(updatedGroups, group)
			}
		}
		cfg.Groups = updatedGroups
	})
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// --- Proxy Handlers ---

func handleAddProxy(cm *manager.ConfigManager, w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/", http.StatusMethodNotAllowed)
		return
	}
	name := strings.TrimSpace(r.FormValue("name"))
	proxyType := config.ProxyType(r.FormValue("type"))
	listenAddress := strings.TrimSpace(r.FormValue("listen_address"))

	if name == "" {
		httpError(w, "Proxy name cannot be empty.", nil, http.StatusBadRequest)
		return
	}

	// mDNS reflector is a special case that doesn't use a listen address.
	// All other types currently supported by the UI require one.
	if proxyType != config.MDNSReflector && listenAddress == "" {
		httpError(w, "Listen address cannot be empty for this proxy type.", nil, http.StatusBadRequest)
		return
	}

	// Check for duplicate names before updating the config.
	for _, p := range cm.Get().Proxies {
		if p.Name == name {
			httpError(w, fmt.Sprintf("Proxy with name '%s' already exists.", name), nil, http.StatusBadRequest)
			return
		}
	}

	newProxy := config.ProxyConfig{
		Name:          name,
		Type:          proxyType,
		ListenAddress: listenAddress,
		Enabled:       true,
	}
	cm.Update(func(cfg *config.Config) {
		cfg.Proxies = append(cfg.Proxies, newProxy)
	})
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func handleUpdateProxy(cm *manager.ConfigManager, w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/", http.StatusMethodNotAllowed)
		return
	}
	originalName := r.FormValue("original_name")
	cm.Update(func(cfg *config.Config) {
		for i := range cfg.Proxies {
			if cfg.Proxies[i].Name == originalName {
				cfg.Proxies[i].Name = r.FormValue("name")
				cfg.Proxies[i].ListenAddress = r.FormValue("listen_address")
				break
			}
		}
	})
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func handleToggleProxy(cm *manager.ConfigManager, w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/", http.StatusMethodNotAllowed)
		return
	}
	proxyName := r.FormValue("name")
	cm.Update(func(cfg *config.Config) {
		for i := range cfg.Proxies {
			if cfg.Proxies[i].Name == proxyName {
				cfg.Proxies[i].Enabled = !cfg.Proxies[i].Enabled
				break
			}
		}
	})
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func handleToggleProxyAuth(cm *manager.ConfigManager, w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/", http.StatusMethodNotAllowed)
		return
	}
	proxyName := r.FormValue("proxy_name")
	cm.Update(func(cfg *config.Config) {
		for i := range cfg.Proxies {
			if cfg.Proxies[i].Name == proxyName {
				cfg.Proxies[i].Auth.Enabled = !cfg.Proxies[i].Auth.Enabled
				break
			}
		}
	})
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func handleDeleteProxy(cm *manager.ConfigManager, w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/", http.StatusMethodNotAllowed)
		return
	}
	proxyName := r.FormValue("name")
	cm.Update(func(cfg *config.Config) {
		var updatedProxies []config.ProxyConfig
		for _, proxy := range cfg.Proxies {
			if proxy.Name != proxyName {
				updatedProxies = append(updatedProxies, proxy)
			}
		}
		cfg.Proxies = updatedProxies
	})
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// --- Policy Handlers ---

func parsePolicyForm(r *http.Request) config.Policy {
	if err := r.ParseForm(); err != nil {
		log.Warn().Err(err).Msg("Could not parse policy form")
	}
	conditions := config.Conditions{}
	conditions.ClientGroups = r.Form["client_groups"]
	if destHosts := strings.TrimSpace(r.FormValue("dest_hosts")); destHosts != "" {
		conditions.DestHosts = strings.Split(destHosts, ",")
	}
	if destPortsStr := strings.TrimSpace(r.FormValue("dest_ports")); destPortsStr != "" {
		portStrings := strings.Split(destPortsStr, ",")
		for _, portStr := range portStrings {
			if port, err := strconv.Atoi(strings.TrimSpace(portStr)); err == nil {
				conditions.DestPorts = append(conditions.DestPorts, port)
			}
		}
	}
	for _, dayStr := range r.Form["days_of_week"] {
		conditions.DaysOfWeek = append(conditions.DaysOfWeek, config.DayOfWeek(dayStr))
	}
	if startTime, endTime := r.FormValue("start_time"), r.FormValue("end_time"); startTime != "" && endTime != "" {
		conditions.TimeOfDay = fmt.Sprintf("%s-%s", startTime, endTime)
	}
	return config.Policy{
		Name:       r.FormValue("name"),
		Action:     config.PolicyAction(r.FormValue("action")),
		Disabled:   r.FormValue("disabled") == "on",
		Conditions: conditions,
	}
}

func handleAddPolicy(cm *manager.ConfigManager, w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/", http.StatusMethodNotAllowed)
		return
	}
	proxyName := r.FormValue("proxy_name")
	newPolicy := parsePolicyForm(r)
	cm.Update(func(cfg *config.Config) {
		for i := range cfg.Proxies {
			if cfg.Proxies[i].Name == proxyName {
				cfg.Proxies[i].Policies = append(cfg.Proxies[i].Policies, newPolicy)
				break
			}
		}
	})
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func handleUpdatePolicy(cm *manager.ConfigManager, w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/", http.StatusMethodNotAllowed)
		return
	}
	proxyName := r.FormValue("proxy_name")
	originalPolicyName := r.FormValue("original_name")
	updatedPolicy := parsePolicyForm(r)
	cm.Update(func(cfg *config.Config) {
		for i := range cfg.Proxies {
			if cfg.Proxies[i].Name == proxyName {
				for j := range cfg.Proxies[i].Policies {
					if cfg.Proxies[i].Policies[j].Name == originalPolicyName {
						cfg.Proxies[i].Policies[j] = updatedPolicy
						break
					}
				}
				break
			}
		}
	})
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func handleTogglePolicy(cm *manager.ConfigManager, w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/", http.StatusMethodNotAllowed)
		return
	}
	proxyName := r.FormValue("proxy_name")
	policyName := r.FormValue("policy_name")
	cm.Update(func(cfg *config.Config) {
		for i := range cfg.Proxies {
			if cfg.Proxies[i].Name == proxyName {
				for j := range cfg.Proxies[i].Policies {
					if cfg.Proxies[i].Policies[j].Name == policyName {
						cfg.Proxies[i].Policies[j].Disabled = !cfg.Proxies[i].Policies[j].Disabled
						break
					}
				}
				break
			}
		}
	})
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func handleDeletePolicy(cm *manager.ConfigManager, w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/", http.StatusMethodNotAllowed)
		return
	}
	proxyName := r.FormValue("proxy_name")
	policyName := r.FormValue("policy_name")
	cm.Update(func(cfg *config.Config) {
		for i := range cfg.Proxies {
			if cfg.Proxies[i].Name == proxyName {
				var updatedPolicies []config.Policy
				for _, p := range cfg.Proxies[i].Policies {
					if p.Name != policyName {
						updatedPolicies = append(updatedPolicies, p)
					}
				}
				cfg.Proxies[i].Policies = updatedPolicies
				break
			}
		}
	})
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// --- Auth Handlers ---

func handleAddUser(cm *manager.ConfigManager, w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/", http.StatusMethodNotAllowed)
		return
	}
	proxyName := r.FormValue("proxy_name")
	username := r.FormValue("username")
	password := r.FormValue("password")

	if username == "" || password == "" {
		httpError(w, "Username and password cannot be empty", nil, http.StatusBadRequest)
		return
	}

	hash, err := generateArgon2idHash(password)
	if err != nil {
		httpError(w, "Failed to hash password", err, http.StatusInternalServerError)
		return
	}

	newUser := config.User{Username: username, Password: hash}

	cm.Update(func(cfg *config.Config) {
		for i := range cfg.Proxies {
			if cfg.Proxies[i].Name == proxyName {
				userExists := false
				for _, u := range cfg.Proxies[i].Auth.Users {
					if u.Username == username {
						userExists = true
						break
					}
				}
				if !userExists {
					cfg.Proxies[i].Auth.Users = append(cfg.Proxies[i].Auth.Users, newUser)
				}
				break
			}
		}
	})

	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func handleDeleteUser(cm *manager.ConfigManager, w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/", http.StatusMethodNotAllowed)
		return
	}
	proxyName := r.FormValue("proxy_name")
	username := r.FormValue("username")

	cm.Update(func(cfg *config.Config) {
		for i := range cfg.Proxies {
			if cfg.Proxies[i].Name == proxyName {
				var updatedUsers []config.User
				for _, user := range cfg.Proxies[i].Auth.Users {
					if user.Username != username {
						updatedUsers = append(updatedUsers, user)
					}
				}
				cfg.Proxies[i].Auth.Users = updatedUsers
				break
			}
		}
	})

	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func generateArgon2idHash(password string) (string, error) {
	const (
		memory      = 64 * 1024
		iterations  = 1
		parallelism = 4
		saltLength  = 16
		keyLength   = 32
	)

	salt := make([]byte, saltLength)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}

	hash := argon2.IDKey([]byte(password), salt, iterations, memory, parallelism, keyLength)

	b64Salt := base64.RawStdEncoding.EncodeToString(salt)
	b64Hash := base64.RawStdEncoding.EncodeToString(hash)

	hashString := fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s", argon2.Version, memory, iterations, parallelism, b64Salt, b64Hash)
	return hashString, nil
}
