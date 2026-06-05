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
failregex = IP=<HOST> COUNTRY=[A-Z]{2} URI=.*
ignoreregex =
```

### 2. Action (To ban a range of Ips)

```bash
nano /etc/fail2ban/action.d/iptables-cidr24.conf
```

```bash
[Definition]
actionban = ip=$(echo <ip> | cut -d. -f1-3); iptables -I INPUT -s $ip.0/24 -j DROP
actionunban = ip=$(echo <ip> | cut -d. -f1-3); iptables -D INPUT -s $ip.0/24 -j DROP
actionstart =
actionstop =
actioncheck =
```

### 3. Jail

```bash
nano /etc/fail2ban/jail.d/country.conf
```

```bash
[wp-country]
enabled = true
filter = wp-country
logpath = /{ABSOLUTE-PATH}/wp-content/uploads/wpff-blocked-ips.log
maxretry = 1
bantime = 86400
findtime = 600
action = iptables-cidr24[name=wp-country, port=http, protocol=tcp]
```

### 4. Restart Fail2Ban

```bash
service fail2ban restart
```

### 5. Check status

```bash
fail2ban-client status wp-country
```