# Wp-country-blocker
## Description
A WordPress plugin to block access to the website based on the visitor's country.

## Fail2Ban config (à ajouter côté serveur)
### 1. Filter

```bash
nano /etc/fail2ban/filter.d/wp-country.conf
```

```bash
[Definition]
failregex = \[.*\] BLOCKED IP=<HOST> COUNTRY=.* URI=.*
ignoreregex =
```

### 2. Jail

```bash
nano /etc/fail2ban/jail.local
```

```bash
[wp-country]
enabled = true
filter = wp-country
logpath = /wp-content/uploads/wpff-blocked-ips.log
maxretry = 1
bantime = 86400
findtime = 600
```

### 3. Restart Fail2Ban

```bash
service fail2ban restart
```