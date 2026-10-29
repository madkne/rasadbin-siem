package detection

import "strings"

func isSYNPacket(msg string) bool {
	// TCP SYN flag = 0x02, SYN-ACK = 0x12.
	// Match flags=0x02 exactly (SYN without ACK). Messages without a flags
	// marker (legacy/unstructured) are treated as scan attempts.
	if !strings.Contains(msg, "flags=") {
		return true
	}
	return strings.Contains(msg, "flags=0x02")
}
func matches(r Rule, ev Event) bool {
	if len(r.Sources) > 0 {
		ok := false
		for _, s := range r.Sources {
			if strings.EqualFold(strings.TrimSpace(s), ev.Source) {
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
	}
	msg := strings.ToLower(ev.Message)
	for _, term := range r.MatchAny {
		if strings.Contains(msg, strings.ToLower(term)) {
			return true
		}
	}
	switch r.Kind {
	case "ssh_brute_force":
		return strings.Contains(msg, "sshd") && (strings.Contains(msg, "failed password") || strings.Contains(msg, "authentication failure") || strings.Contains(msg, "invalid user"))
	case "port_scan":
		if !strings.Contains(strings.ToLower(ev.Source), "network") {
			return false
		}
		msg := strings.ToLower(ev.Message)
		// Only scan-like events: TCP packets. SYN filtering happens in
		// Process via isSYNPacket when flags are present.
		return strings.Contains(msg, "tcp")
	case "auth_failures":
		return containsAny(msg, "failed password", "authentication failure", "authentication failed", "auth failure", "invalid user", "pam_unix", "failed login", "login failed")
	case "threshold":
		return len(r.MatchAny) == 0
	default:
		return false
	}
}
func groupKey(r Rule, ev Event) string {
	switch r.Kind {
	case "port_scan":
		if ip := extractSourceIP(ev.Message); ip != "" {
			return ip
		}
	case "ssh_brute_force", "auth_failures":
		if ip := extractSourceIP(ev.Message); ip != "" {
			return ip
		}
	}
	return ev.Source + "|" + extractSourceIP(ev.Message)
}
func extractSourceIP(s string) string {
	// Handles sshd "from 192.0.2.1", and packet strings "192.0.2.1:123 -> ...".
	fields := strings.Fields(s)
	for i, f := range fields {
		candidate := strings.Trim(f, "[](),;")
		if strings.EqualFold(candidate, "from") && i+1 < len(fields) {
			candidate = strings.Trim(fields[i+1], "[](),;")
		}
		if j := strings.LastIndex(candidate, ":"); j > 0 && strings.Count(candidate, ":") == 1 {
			candidate = candidate[:j]
		}
		if strings.Contains(candidate, ".") {
			parts := strings.Split(candidate, ".")
			if len(parts) == 4 {
				valid := true
				for _, p := range parts {
					if p == "" {
						valid = false
						break
					}
					for _, c := range p {
						if c < '0' || c > '9' {
							valid = false
							break
						}
					}
				}
				if valid {
					return candidate
				}
			}
		}
	}
	return ""
}
func containsAny(s string, terms ...string) bool {
	for _, t := range terms {
		if strings.Contains(s, t) {
			return true
		}
	}
	return false
}
func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

func destinationPort(s string) string {
	i := strings.Index(s, " -> ")
	if i < 0 {
		return ""
	}
	right := strings.Fields(s[i+4:])
	if len(right) == 0 {
		return ""
	}
	hostport := strings.Trim(right[0], "[](),;")
	j := strings.LastIndex(hostport, ":")
	if j < 0 || j == len(hostport)-1 {
		return ""
	}
	port := hostport[j+1:]
	for _, c := range port {
		if c < '0' || c > '9' {
			return ""
		}
	}
	return port
}
