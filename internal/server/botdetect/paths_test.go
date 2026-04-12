package botdetect

import "testing"

func TestIsSuspiciousPath(t *testing.T) {
	cases := []struct {
		path    string
		wantHit bool
	}{
		{"/.env", true},
		{"/.git/config", true},
		{"/wp-admin/login.php", true},
		{"/phpMyAdmin/", true},
		{"/etc/passwd", true},
		{"/admin", false},
		{"/actuator/health", true},
		{"/index.html", false},
		{"/api/users", false},
		{"/static/app.js", false},
		// URL-encoded bypass attempts
		{"/.%65nv", true},        // encoded 'e' in .env
		{"/wp-ad%6Din", true},    // encoded 'm' in wp-admin
		// Path normalisation bypass attempts
		{"//wp-admin", true},     // double slash
		{"/./wp-admin", true},    // dot segment
		// Case variants
		{"/WP-ADMIN/login", true}, // uppercase
		{"/.GIT/config", true},    // uppercase .git
	}
	for _, c := range cases {
		t.Run(c.path, func(t *testing.T) {
			if got := isSuspiciousPath(c.path); got != c.wantHit {
				t.Errorf("isSuspiciousPath(%q) = %v, want %v", c.path, got, c.wantHit)
			}
		})
	}
}
