# Netflow exporter

`./flow [-f file] [-c host[:port] [-a active_timeout] [-inactive_timeout] [-m count]`

`-f file` - Read the input pcap from `file`.
Default is `stdin`.

`-c host[:port]` - The NetFlow records are sent to the collector at `host:port`.
Default is `127.0.0.1:2055`.

`-a active_timeout` - Sets the active timeout to `active_timeout` seconds. If a flow is active for at least `active_timeout` seconds, it gets exported to the collector.
Default is `60`.

`-i inactive_timeout` - Sets the inactive timeout to `inactive_timeout` seconds. If a flow is inactive for at least `inactive_timeout` seconds, it gets exported to the collector. Default is `10`.

`-m count` - Sets the flow-cache size to `count`. If the flow-cache gets full, the oldest flow is automatically exported to the collector.
Default is `1024`.
