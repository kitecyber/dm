# dm-cmd
Device-Manager command line interface binary

## Operating systems and compatibility 

- dns 
    - Currently dns functionality is supported on Windows and Linux. Mac yet to be tested.
    - dns can be setup and also can be viewed.

- firewall
    - Currently firewall functionality is supported on Windows and Mac. Linux yet to be implemented.
    - firewall can be setup and can also be viewed.
- sudo or run as administrator is must to run all these commands.
- Internally based on operating system different tools are used.
- For dns  Windows uses netsh ,darwin uses networksetup and Linux uses nmcli, commands.
- For firewall Windows uses netsh, darwin uses pfctl and writing to /etc/pf.conf file.

## To get help

```
dm-cmd help
dm-cmd dns --help
dm-cmd dns show --help
dm-cmd firewall --help
dm-cmd firewall show --help
```

## To setup dns

```
dm-cmd.exe dns --pd="8.8.8.8" --sd="8.8.4.4"
```
## To view dns settings

```
dm-cmd.exe dns show
```

## To setup firewall
- firewall name is mandatory
- if no protocol is given it takes any as protocol
- if no port is given it takes any as port
- if no reportip address is given it takes any as remoteip
- action must be given as allow or block
- direction must be in or out. Default is taken as in. in --> inbound,out --> outbound
- remoteip cidr notation is supported
- Currently port ranges are not supported.
- Darwin based systems do not support rule name(s), hence rule name is used as an anchor. That is used to group firewall rules.
- firewall settings are shown as per system format.

```
dm-cmd.exe firewall -n "dm-demo-rule-2" -p tcp -a allow -d in -r 45000 -i 1.1.10.10

dm-cmd.exe firewall -n "dm-demo-rule-2" -p udp -a allow
```
## To view firewall settings

```
dm-cmd.exe firewall show -n "dm-demo-rule-2"
```