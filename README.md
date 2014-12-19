Apache module for REMOTE_ADDR environment variable's value replacement
==========

[![License](http://img.shields.io/badge/license-Apache%202.0-green.svg)](http://www.apache.org/licenses/LICENSE-2.0)

This module provides a hook that is replace by user-defined http header variable's value from REMOTE_ADDR environment variable's value.
REMOTE_ADDR environment variable's value is changed to user-defined http header variable's value when this module is enabled.
User-defined http header variable name is like [X-Forwarded-For](http://en.wikipedia.org/wiki/X-Forwarded-For), X-{YOUR_DEFINED}-For, {YOUR_DEFINED}.

## Dependencies
* Apache(1|2)
* Apxs

## Installation

```
shell> git clone git://github.com/vozlt/mod_remoteaddr.git
```

If apache1
```
shell> cd mod_remoteaddr/apache1
```

If apache2
```
shell> cd mod_remoteaddr/apache2
```

```
shell> apxs -iac mod_remoteaddr.c
```

## Configuration(httpd.conf)

```ApacheConf
AddModule mod_remoteaddr.c

<IfModule mod_remoteaddr.c>
    # Hooking Header Name (TAKE12 - one or two arguments)
    HookVarName         X-Forwarded-For

    # Select only one IP address (Left|Right)
    SelectX             Left

    # Original IP Save
    SaveVarName         REMOTE_ADDR_SAVE

    # Hooking ($REMOTE_ADDR, access_log)
    IntVarHook          On

    # Scoreboard Hooking (server-status)
    ScoreVarHook        On
</IfModule>
```

##### HookVarName
````ApacheConf
# Syntax
HookVarName        {USER_DEFINED_STRING}
HookVarName        {USER_DEFINED_STRING1} {USER_DEFINED_STRING2}
````

The HookVarName directive sets the request header name like X-Forwarded-For.
If first argument's value is false, second argument's value will be check.

##### SelectX
````ApacheConf
# Syntax
SelectX        {Left|Right}
````

The SelectX directive choose between the left or right's value which is a comma+space separated list of IP addresses.

X-Forwarded-For's general format of the field is:
```
X-Forwarded-For: client, proxy1, proxy2
```
where the value is a comma+space separated list of IP addresses, the left-most being the original client,
and each successive proxy that passed the request adding the IP address where it received the request from.
In this example, the request passed through proxy1, proxy2, and then proxy3 (not shown in the header).
proxy3 appears as remote address of the request.


##### SaveVarName
````ApacheConf
# Syntax
SaveVarName        {STRING}
````

The SaveVarName directive sets the environment variable name.
The environment variable name's value is set to be the original ip address.


##### IntVarHook
````ApacheConf
# Syntax
IntVarHook        {On|Off}
````

The IntVarHook directive sets the enable or disable of main hook.

1. REMOTE_ADDR is changed to HookVarName's value.
2. Access_log is changed to HookVarName's value.


##### ScoreVarHook
````ApacheConf
# Syntax
ScoreVarHook        {On|Off}
````

The ScoreVarHook directive sets the enable or disable of scoreboard(server-status) hook.

1. Scoreboard(server-status)'s client(ip address) is changed to HookVarName's value.

## Author
YoungJoo.Kim [<vozlt@vozlt.com>]
