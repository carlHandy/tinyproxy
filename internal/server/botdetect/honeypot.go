package botdetect

import (
	"fmt"
	"log"
	"math/rand"
	"net/http"
	"strings"
	"time"
)

// serveHoneypot logs the probe, introduces a short random delay to slow down
// automated scanners, then returns convincing fake content matching the path.
// It always responds 200 so the attacker cannot distinguish it from a real hit.
func serveHoneypot(w http.ResponseWriter, r *http.Request) {
	log.Printf("HONEYPOT ip=%s ua=%q path=%q", r.RemoteAddr, r.Header.Get("User-Agent"), r.URL.Path)

	// Random delay 150–750 ms — burns scanner threads without exhausting ours.
	time.Sleep(time.Duration(150+rand.Intn(600)) * time.Millisecond)

	p := strings.ToLower(r.URL.Path)
	switch {
	case strings.HasPrefix(p, "/.env"):
		honeypotEnv(w)
	case strings.HasPrefix(p, "/.git"):
		honeypotGit(w)
	case strings.HasPrefix(p, "/.htaccess"):
		honeypotHtaccess(w)
	case strings.HasPrefix(p, "/.aws"):
		honeypotAWS(w)
	case strings.HasPrefix(p, "/wp-admin"), strings.HasPrefix(p, "/wp-login"):
		honeypotWordPress(w)
	case strings.HasPrefix(p, "/phpmyadmin"):
		honeypotPhpMyAdmin(w)
	case strings.HasPrefix(p, "/actuator"):
		honeypotActuator(w)
	case strings.HasPrefix(p, "/console"):
		honeypotConsole(w)
	case strings.HasPrefix(p, "/config.json"):
		honeypotConfigJSON(w)
	case strings.HasPrefix(p, "/credentials"):
		honeypotCredentials(w)
	default:
		honeypotGeneric(w)
	}
}

func honeypotEnv(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/plain")
	fmt.Fprint(w, `APP_NAME=production-app
APP_ENV=production
APP_KEY=base64:kDHu9rsBbmhpCFNNECRdBlKTMNuPpzHmQlMBSohy3sA=
APP_DEBUG=false
APP_URL=https://localhost

DB_CONNECTION=mysql
DB_HOST=127.0.0.1
DB_PORT=3306
DB_DATABASE=prod_db
DB_USERNAME=db_admin
DB_PASSWORD=oHDy0VZuypcuQfiYdfrzHEU76e3CsJN0YgDut4M1d

AWS_ACCESS_KEY_ID=AKIAHONEYPOT00FAKE1
AWS_SECRET_ACCESS_KEY=n7zoJ2khDBxLt2GAVxFi6MJXy8TDwEyhzmGGbEkMk
AWS_DEFAULT_REGION=us-east-1
AWS_BUCKET=prod-assets-bucket

STRIPE_KEY=pk_live_Q5cGrH54gTmj7LBAe113cg2oD4w8u
STRIPE_SECRET=sk_live_XVxMPxcfBHsChm2aKVFG19Ndts6nBJ

MAIL_MAILER=smtp
MAIL_HOST=smtp.mailgun.org
MAIL_PORT=587
MAIL_USERNAME=postmaster@handy.gy
MAIL_PASSWORD=GGJRiGHhH5cYB1f2Wx
`)
}

func honeypotGit(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/plain")
	fmt.Fprint(w, `[core]
	repositoryformatversion = 0
	filemode = true
	bare = false
	logallrefupdates = true
[remote "origin"]
	url = git@github.com:example/private-repo.git
	fetch = +refs/heads/*:refs/remotes/origin/*
[branch "main"]
	remote = origin
	merge = refs/heads/main
`)
}

func honeypotHtaccess(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/plain")
	fmt.Fprint(w, `Options -Indexes
ServerSignature Off

<IfModule mod_rewrite.c>
    RewriteEngine On
    RewriteBase /
    RewriteRule ^index\.php$ - [L]
    RewriteCond %{REQUEST_FILENAME} !-f
    RewriteCond %{REQUEST_FILENAME} !-d
    RewriteRule . /index.php [L]
</IfModule>
`)
}

func honeypotAWS(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/plain")
	fmt.Fprint(w, `[default]
aws_access_key_id = k7gmoMp1p4r9BdC3c8
aws_secret_access_key = pwgWuMxgBVfVZdcixGT5CGMan0icjeDnzdJzTy
region = us-east-1
`)
}

func honeypotWordPress(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("X-Powered-By", "PHP/8.2.0")
	fmt.Fprint(w, `<!DOCTYPE html>
<html lang="en-US">
<head>
<meta charset="UTF-8">
<title>Log In &lsaquo; WordPress</title>
<meta name="robots" content="noindex,nofollow">
</head>
<body class="login login-action-login wp-core-ui">
<div id="login">
<h1><a href="https://wordpress.org/">WordPress</a></h1>
<form name="loginform" id="loginform" action="/wp-login.php" method="post">
<p>
<label for="user_login">Username or Email Address</label>
<input type="text" name="log" id="user_login" value="" size="20" autocomplete="username">
</p>
<p>
<label for="user_pass">Password</label>
<input type="password" name="pwd" id="user_pass" size="20" autocomplete="current-password">
</p>
<p class="forgetmenot"><label><input name="rememberme" type="checkbox" value="forever"> Remember Me</label></p>
<p class="submit">
<input type="submit" name="wp-submit" id="wp-submit" value="Log In">
<input type="hidden" name="redirect_to" value="/wp-admin/">
<input type="hidden" name="testcookie" value="1">
</p>
</form>
<p id="nav"><a href="/wp-login.php?action=lostpassword">Lost your password?</a></p>
</div>
</body>
</html>
`)
}

func honeypotPhpMyAdmin(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("X-Powered-By", "PHP/8.2.0")
	fmt.Fprint(w, `<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><title>phpMyAdmin</title></head>
<body>
<div class="container">
<form method="post" action="index.php" name="login_form">
<input type="hidden" name="token" value="honeypot_token">
<div id="login_form">
<h2>phpMyAdmin</h2>
<fieldset>
<legend>Log in</legend>
<label for="input_username">Username:</label>
<input type="text" name="pma_username" id="input_username" value="" size="24" autocomplete="username">
<label for="input_password">Password:</label>
<input type="password" name="pma_password" id="input_password" size="24" autocomplete="current-password">
<label for="select_server">Server:</label>
<select name="server" id="select_server">
<option value="1" selected>127.0.0.1</option>
</select>
</fieldset>
<input type="submit" value="Go" id="input_go">
</div>
</form>
</div>
</body>
</html>
`)
}

func honeypotActuator(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/vnd.spring-boot.actuator.v3+json")
	fmt.Fprint(w, `{
  "status": "UP",
  "components": {
    "db": {
      "status": "UP",
      "details": {"database": "MySQL", "validationQuery": "isValid()"}
    },
    "diskSpace": {
      "status": "UP",
      "details": {"total": 107374182400, "free": 43284750336, "threshold": 10485760, "exists": true}
    },
    "ping": {"status": "UP"}
  }
}`)
}

func honeypotConsole(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, `<!DOCTYPE html>
<html>
<head><title>Management Console</title></head>
<body>
<h2>Management Console</h2>
<form method="post" action="/console/login">
<label>Username: <input name="username" type="text" autocomplete="username"></label><br>
<label>Password: <input name="password" type="password" autocomplete="current-password"></label><br>
<input type="submit" value="Login">
</form>
</body>
</html>
`)
}

func honeypotConfigJSON(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprint(w, `{
  "database": {
    "host": "127.0.0.1",
    "port": 3306,
    "name": "prod_db",
    "user": "admin",
    "password": "tNG5sfCjAmjLmhJgaCkNF5eVHJVi8LUwwtHFUA"
  },
  "redis": {
    "host": "127.0.0.1",
    "port": 6379
  },
  "app": {
    "secret": "Pb9VmapRMU2e4pvpoyCZ1zXDCzYyB6GoBGAr2n",
    "env": "production"
  }
}`)
}

func honeypotCredentials(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/plain")
	fmt.Fprint(w, `[production]
username=admin
password=HONEYPOT-NotReal-xK92mPqL
host=db.internal.example.com
port=5432
`)
}

func honeypotGeneric(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, `<!DOCTYPE html>
<html>
<head><title>404 Not Found</title></head>
<body>
<h1>Not Found</h1>
<p>The requested URL was not found on this server.</p>
</body>
</html>
`)
}
