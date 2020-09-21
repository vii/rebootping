# rebootping network monitor

Rebootping monitors locally connected devices and manages multiple ISP Internet connections.

- monitors all network interfaces and samples a tcpdump pcap file for each MAC address, limited to 100MB
- outputs a report of devices and open ports from passive scanning
- pings external IPs through each network interface independently
- decides which Internet links are healthy and via shorewall integration, uses those for outgoing traffic

## Internet connection selection algorithm

Repeatedly
- count successful ping replies since last send for each interface
- send new pings to all hosts from all interfaces
- mark interfaces unhealthy that do not have the best count of ping replies
- mark at least one interface healthy that has the best count of ping replies, 
and enable others if they have been healthy for one hour
- commit healthy and unhealthy choices to shorewall (if changes made)
- sleep for 1s

## Shorewall integration

[Shorewall](https://shorewall.org/) needs to be configured for multiple providers, which is complex.

Then add this /etc/shorewall/isusable script

```sh
local status
status=0

file=/var/lib/shorewall/rebootping-${1}.status
[ -f $file ] && status=$(cat $file)

return $status
```

When an interface is unhealthy, its status is set to 1.

This means no more new outgoing connections will be masqueraded over the link. 
Connections marked for the link will still try to use it.

## Design starting points

- Network model: he network links are over-provisioned but have occasional glitches; if a glitch happens we expect
another within an hour so keep it disabled.
- Cheap to capture all traffic as even with gigabit links, CPU load is load.
- Few dependencies (libpcap, shorewall).
- Make context available for decisions.

## Ideas for more work

- Systemd script.
- Datastore for history of pings and traffic statistics (RRD?).
- User Interface showing active machines and graphs of traffic.
- Graphs of ping times.
- Integrate UI with DHCPd to conveniently allow renaming and restricting IoT devices.
- IPv6.
- Docker test environment.
- Integrate with wireshark.
