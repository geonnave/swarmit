# `swarmit-provision`

A command-line tool for provisioning DotBot devices and gateways.

```
Usage: swarmit-provision [OPTIONS] COMMAND [ARGS]...

  A tool for provisioning DotBot devices and gateways in the context of a
  SwarmIT-enabled testbed.

Options:
  --help  Show this message and exit.

Commands:
  fetch          Fetch firmware assets into bin/<fw-version>/.
  flash          Flash firmware + config using versioned bin layout.
  flash-bringup  Flash J-Link OB or DAPLink programmer firmware.
  flash-hex      Flash explicit app/net hex files.
  read-config    Read config from the device.
```

## Deploying a testbed

First, download firmware assets:

```bash
swarmit-provision fetch --fw-version v0.7.0
```

Then, to flash a DotBot-v3 while specifying a certain Network ID:

```bash
swarmit-provision flash --device dotbot-v3 --fw-version v0.7.0 --network-id 0100
```

And to flash a Mari Gateway:

```bash
swarmit-provision flash --device gateway --fw-version v0.7.0 --network-id 0100
```

... and it's done!

## Deploying a testbed on fresh robots

If your robot just arrived from factory, first you have to run the `flash-bringup` command.
You can concatenate it with a regular `flash` command so that all happens in sequence with minimal manual work.
Like this:

```bash
swarmit-provision flash-bringup --programmer-firmware jlink -d ../../../programer-files-dotbot && \
  swarmit-provision flash -d dotbot-v3 -f local -n 0100 -s 77
```
... where the `-s` flag stands for `--sn-starting-digits` and serves as a pattern to identify the connected programming probe. In this case it solves a problem where the flash command incorrectly selects the external J-Link probe instead of the dotbot's (most DotBots come from factory with a serial number starting by 77).
