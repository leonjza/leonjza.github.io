+++
description = ""
keywords = [
'sdr', 'hacking', 'gnuradio', 'rfcat'
]
categories = [
'sdr', 'rfcat', 'gnuradio', 'remote'
]
date = "2016-10-08T11:15:00+02:00"
title = "introducing ooktools on-off keying tools for your sdr"
+++

In a [previous post](https://leonjza.github.io/blog/2016/10/02/reverse-engineering-static-key-remotes-with-gnuradio-and-rfcat/), I spoke about a simple static key remote and how to replicate its signal using a small python script and RfCat. As part of the work done there, I set out to write a small tool that should help with some of the tasks involved with this process.

{{< figure src="/images/ooktools/banner.png" >}}

Lets take a look at `ooktools`, how to use it and the internals there of. For those in a rush, the repository can be found here: [https://github.com/leonjza/ooktools](https://github.com/leonjza/ooktools).
<!--more-->

## major features
Some of the major features in `ooktools` include:

- Binary string extraction from wave file recordings.
- Wave file cleanups to remove noise in On-off keying recordings.
- Graphing capabilities for wave files.
- General information extraction of wave files.
- Signal recording and playback using `json` definition files that can be shared.
- Plotting of data from the previously mentioned `json` recordings.
- Signal searching for On-off keying type data.
- Sending signals in both binary, complete PWM formatted or hex strings using an RfCat dongle.
- Gnuradio `.grc` template file generation.

Of course, as I get to spend more time on this, this list may grow and most of the functionality may actually be tested / perfected in environments outside of my lab. There are many cases where stuff breaks too. Checkout the *Known Issues* section in the source repository.

## installation
Installing `ooktools` *should* be as simple as `pip install ooktools`. This should take care of all of the dependencies except for [RfCat](https://bitbucket.org/atlas0fd00m/rfcat). For this you can either `apt install rfcat` in Kali, or install from source from the [RfCat](https://bitbucket.org/atlas0fd00m/rfcat) repository.

## usage
Using `ooktools` should be as simple as just running it with the required arguments. Based on how you chose to install it you can either use the `ooktools` command directly, or invoke the module from a cloned repository with `python -m ooktools.console`:

```
$ ooktools --help
         _   _           _
 ___ ___| |_| |_ ___ ___| |___
| . | . | '_|  _| . | . | |_ -|
|___|___|_,_|_| |___|___|_|___|
On-off keying tools for your SD-arrrR
https://github.com/leonjza/ooktools

Usage: ooktools [OPTIONS] COMMAND [ARGS]...

Options:
  --help  Show this message and exit.

Commands:
  gnuradio  GNU Radio Commands.
  signal    Signal Commands.
  wave      Wave File Commands.
```

A number of *sub commands* exist and are categorized according to their main functions. You can get help at any time by supplying the `--help` argument. The below example shows help for the `signal` sub command:

```
$ ooktools signal --help
         _   _           _
 ___ ___| |_| |_ ___ ___| |___
| . | . | '_|  _| . | . | |_ -|
|___|___|_,_|_| |___|___|_|___|
On-off keying tools for your SD-arrrR
https://github.com/leonjza/ooktools

Usage: ooktools signal [OPTIONS] COMMAND [ARGS]...

  Signal Commands.

Options:
  --help  Show this message and exit.

Commands:
  play    Play frames from a source file.
  plot    Plot frames from a recorded signal.
  record  Record frames to a file.
  search  Search for signals.
  send    Send signals using a RFCat dongle.
```

## examples
For the rest of the post, I am going to cover some examples to showcase what is possible with `ooktools`. Like I have previously mentioned, a lot of the functionality and testing was done in my isolated lab environment, and may actually not work at all for you. Keep this in mind! ;)

### wave binary
The `ooktools wave binary` command can be used to attempt to extract the binary string from a wave file recording. Lets take a sample recording where I extracted a single pulse:

{{< figure src="/images/ooktools/audacity_single_pulse.png" >}}

Spotting the key with your eye may be easy in this case, but its a lot harder with longer waves. Anyways, running `ooktools wave binary` for this recording should output the binary sequence.

{{< figure src="/images/ooktools/ooktools_wave_binary.png" >}}

### wave clean
The `ooktools wave clean` command takes a source wave file and tries to *'square out'* the signal, removing any jumps in the waveform.

{{< figure src="/images/ooktools/wave_clean.png" >}}

The source and destinations files compared after this command can be seen in this screenshot:


{{< figure src="/images/ooktools/audacity_clean.png" >}}

### wave graph
The `ooktools wave graph` command plots the values read from a wave file source. You can interactively pan and zoom the graph to focus on specific areas as needed.

{{< figure src="/images/ooktools/wave_graph.png" >}}

### signal search
The `ooktools signal search` commands attempts to find valid on-off keying packets while iterating over a frequency range that is specified. The definition of a *valid packet* is currently still a little strange though. :|

To best show this feature, the following asciinema recording attempts to show the `signal search` in action while I hold down the button on my remote:

<script type="text/javascript" src="https://asciinema.org/a/88503.js" id="asciicast-88503" async></script>

## signal record
The `ooktools signal record` command allows you to record a number of frames to a file as you press down on a remote repeatedly. This can then be plotted or simply played back at a later stage.

{{< figure src="/images/ooktools/signal_record.png" >}}

## signal play
The `ooktools signal play` command allows you to replay frames recorded using `ooktools signal record`. It literally just plays the frames back.

{{< figure src="/images/ooktools/signal_play.png" >}}

## signal plot
The `ooktools signal plot` command allows you to create plots of the frames that were recorded using `ooktools signal record`. This could be used to very quickly get an idea of the on-off key that may be present on a remote.

{{< figure src="/images/ooktools/signal_plot.png" >}}

## signal send
The `ooktools signal send` sub command helps with sending signals either as binary codes, full PWM codes or hex strings. Example usage of the binary string method is:

{{< figure src="/images/ooktools/send_binary_data.png" >}}

The same code as a hex string would be:

{{< figure src="/images/ooktools/send_hex_data.png" >}}


## internals and development
I am sure as more time is spent on the toolkit it will evolve and become a little refined. However, if you wish to hack away at it, hopefully the following bit will help in getting you to understand how its put together.

`ooktools` is build around the excellent python [Click](http://click.pocoo.org/6/) cli framework. The applications entry point as defined in `setup.py` as the `cli()` method in `ooktools.console`. This is standard bootstrapping to reach the `cli()` method. Commands themselves are decorated using the `@group.command()` decorator and is grouped according to primary function.

Once you checked out the `console.py` source, you may notice that this file only really handles the commands and arguments to other functions that are defined in `ooktools.commands`. It is also responsible for calling the correct validation methods as defined in `ooktools.validators`.

Once a command is happy with its arguments, the **actual** work is then in the `ooktools.commands.category` scripts.

As far as dependencies go, at the time of writing `ooktools` depends on *bitstring*, *click*, *matplotlib*, *numpy* and *peakutils*. There is also a requirement for `rflib` which comes from the [RfCat](https://bitbucket.org/atlas0fd00m/rfcat) repository.
