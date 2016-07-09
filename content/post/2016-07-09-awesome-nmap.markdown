+++
categories = ['how to', 'notes', 'nmap']
date = "2016-07-09T15:55:48+02:00"
description = ""
keywords = ['nmap', 'grep', 'awesome']
title = "awesome nmap grep"

+++

Nmap's greppable output is really handy. Saving greppable output from a scan means the output is delimited in a way that can be easily processed using tools such as `grep`, `sed`, `cut` and `awk`.

{{< figure src="/images/nmap-project-logo.png" >}}

This post shows a few examples of post scan processing of the greppable output produced with the `-oG` flag. A more up to date repository with examples and command explanations can be found in my [awesome-nmap-grep](https://github.com/leonjza/awesome-nmap-grep) github repository.
<!--more-->

## keep in mind
All of the below commands assume an environment variable `NMAP_FILE` is set. This is simply the location of the output from nmaps `-oG`.

### Count Number of Open Ports

#### command
```bash
NMAP_FILE=output.grep

egrep -v "^#|Status: Up" $NMAP_FILE | cut -d' ' -f2 -f4- | \
sed -n -e 's/Ignored.*//p' | \
awk -F, '{split($0,a," "); printf "Host: %-20s Ports Open: %d\n" , a[1], NF}' \
| sort -k 5 -g
```

#### output
```bash
Host: 127.0.0.1            Ports Open: 16
```

### Top 10 Open Ports

#### command
```bash
NMAP_FILE=output.grep

egrep -v "^#|Status: Up" $NMAP_FILE | cut -d' ' -f4- | \
sed -n -e 's/Ignored.*//p' | tr ',' '\n' | sed -e 's/^[ \t]*//' | \
sort -n | uniq -c | sort -k 1 -r | head -n 10
```

#### output
```bash
1 9001/open/tcp//tor-orport?///
1 9000/open/tcp//cslistener?///
1 8080/open/tcp//http-proxy///
1 80/open/tcp//http//Caddy/
1 6379/open/tcp//redis//Redis key-value store/
1 631/open/tcp//ipp//CUPS 2.1/
1 6234/open/tcp/////
1 58377/filtered/tcp/////
1 53/open/tcp//domain//dnsmasq 2.76/
1 49153/open/tcp//mountd//1-3/
```

### Hosts and Open Ports

#### command
```bash
NMAP_FILE=output.grep

egrep -v "^#|Status: Up" $NMAP_FILE | cut -d' ' -f2 -f4- | \
sed -n -e 's/Ignored.*//p'  | \
awk '{print "Host: " $1 " Ports: " NF-1; $1=""; for(i=2; i<=NF; i++) { a=a" "$i; }; split(a,s,","); for(e in s) { split(s[e],v,"/"); printf "%-8s %s/%-7s %s\n" , v[2], v[3], v[1], v[5]}; a="" }'
```

#### output
```bash
Host: 127.0.0.1 Ports: 16
open     tcp/22    ssh
open     tcp/53    domain
open     tcp/80    http
open     tcp/443   https
open     tcp/631   ipp
open     tcp/3306  mysql
open     tcp/4767  unknown
open     tcp/6379
open     tcp/8080  http-proxy
open     tcp/8081  blackice-icecap
open     tcp/9000  cslistener
open     tcp/9001  tor-orport
open     tcp/49152 unknown
open     tcp/49153 unknown
filtered tcp/54695
filtered tcp/58369
```

As mentioned in the beginning, more up to date examples are available in the [awesome-nmap-grep](https://github.com/leonjza/awesome-nmap-grep) github repository.
