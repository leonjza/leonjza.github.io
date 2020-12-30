---
categories:
- Nessus
- PHP
- API
comments: true
date: 2013-05-24T00:00:00Z
published: true
title: Hello World! Oh and here's some code!
---

### Introduction

Finally! A blog engine I like! :) No exceptionally bloated backend database with plugins that just get hacked. Yup, slim and sleek. *And*, I get to make posts using Vi :D
Want in on this love? Have a look at [Octopress](http://octopress.org) . Yes, it was a real ball ache to get setup thanks to the ruby dependencies, but now that were rollin' this should be good :D

<!--more-->

### Frustrations breed Ideas
In my day job, I am exposed to a lot of work that will relate around the [Nessus Vulnerability Scanner](http://www.tenable.com/products/nessus).
Originally, interfacing with this scanner used be via a old and clunky *flash* interface. It was bad. They have since moved over to a HTML5, ajaxy interface that is light years better. However, for my needs, the default Nessus Interface just does not cut it.

### Open source? Where do I start?
Based on this old crappy interface, and the need to be able to automate things, I pulled closer the XMLRPC API reference [documentation](http://static.tenable.com/documentation/nessus_5.0_XMLRPC_protocol_guide.pdf). Reading this revealed the API is actually very straight forward. Login -> get a token -> make POST with this token and receive XML. Great.

I started hacking away at some PHP to test this out. Back then I was really _very_ new to this ''development'' thing, so it was really tough to get my head around the concepts of working with the API. Nonetheless, we had something to work with, and this was implemented internally for numerous functions.

Since then, `nessus.php` was born. The first iteration of this code was, well, worse than it is now, but its now very easy to use ( I believe ).

### Instantiate a NessusInterface instance
To use this API, we first need to include it in our script, and then init the Class. Effectively, this will log into the scanner using the provided arguments and store the token in the object. Should it fail, it will raise an error.

```php
<?php
require "nessus.php";

try {
    $api = new NessusInterface(
        $__url,
        $__port,
        $__username,
        $__password
    );
} catch(Exception $e) {
    preprint($e->getMessage());
}
```

#### Do some API calls
Once you have the `$api` variable setup with a instance of __NessusInterface__, you can use any of the available calls. Most of the API calls will return some form of array:

```php
<?php
try {

    $api->feed();
    # // Will return an array like:
    #  Array
    #  (
    #    [feed] => ProFeed
    #    [server_version] => 5.2.1
    #    [web_server_version] => 4.0.37 (Build H20130515A)
    #    [expiration] => 1406174400
    #    [msp] => FALSE
    #    [loaded_plugin_set] => 201305240915
    #    [expiration_time] => 425
    # )

} catch(Exception $e) {

    preprint($e->getMessage());
}
```

Reading the sources will reveal the structures of the returned arrays.
Get the code [here](https://github.com/th3l33k/php-nessus-api)

### Its the small things
This is by no means and elaborate "solution" really. It's purely another building block for something bigger. A believe there are quite a few fundamentals that the Nessus Scanner does not cover, but perhaps that is beyond the scope of what its designed to do :) 

