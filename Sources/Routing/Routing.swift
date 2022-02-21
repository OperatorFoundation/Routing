//
//  Routing.swift
//  Routing
//
//  Created by Jeremy Zunker on 9/25/20.
//

import Foundation
import Datable


//FIXME: move/add input validation from TunTesterCli to TunDevice
//FIXME: change to ioctls?
//FIXME: add get functionality for address, IP forwarding, route
//FIXME: change get functions to return structs instead of a string to make checking settings easier
//FIXME: add remove address functionality
//FIXME: add DNS functionality
//FIXME: add MacOS support
//FIXME: make more generic/universal
//FIXME: write tests

struct Routing {
    var text = "Hello, World!"
}

public func setAddress(interfaceName: String, addressString: String, subnetString: String) -> Bool
{

    /*
        notes on linux tun using strace

        //create a tun interface
        sudo ip tuntap add mode tun
            socket(AF_NETLINK, SOCK_RAW|SOCK_CLOEXEC, NETLINK_ROUTE) = 3
            setsockopt(3, SOL_SOCKET, SO_SNDBUF, [32768], 4) = 0
            setsockopt(3, SOL_SOCKET, SO_RCVBUF, [1048576], 4) = 0
            setsockopt(3, SOL_NETLINK, NETLINK_EXT_ACK, [1], 4) = 0
            bind(3, {sa_family=AF_NETLINK, nl_pid=0, nl_groups=00000000}, 12) = 0
            getsockname(3, {sa_family=AF_NETLINK, nl_pid=7134, nl_groups=00000000}, [12]) = 0
            openat(AT_FDCWD, "/dev/net/tun", O_RDWR) = 4
            ioctl(4, TUNSETIFF, 0x7ffd9ca7adc0)     = 0
            ioctl(4, TUNSETPERSIST, 0x1)            = 0


        //set address and bring up a tun interface
        sudo ifconfig tun0 10.0.8.99/24 up
            ioctl(4, SIOCSIFADDR, {ifr_name="tun0", ifr_addr={sa_family=AF_INET, sin_port=htons(0), sin_addr=inet_addr("10.0.8.99")}}) = 0
            ioctl(4, SIOCGIFFLAGS, {ifr_name="tun0", ifr_flags=IFF_POINTOPOINT|IFF_NOARP|IFF_MULTICAST}) = 0
            ioctl(4, SIOCSIFFLAGS, {ifr_name="tun0", ifr_flags=IFF_UP|IFF_POINTOPOINT|IFF_RUNNING|IFF_NOARP|IFF_MULTICAST}) = 0
            ioctl(4, SIOCGIFFLAGS, {ifr_name="tun0", ifr_flags=IFF_UP|IFF_POINTOPOINT|IFF_NOARP|IFF_MULTICAST}) = 0
            ioctl(4, SIOCSIFFLAGS, {ifr_name="tun0", ifr_flags=IFF_UP|IFF_POINTOPOINT|IFF_RUNNING|IFF_NOARP|IFF_MULTICAST}) = 0
            ioctl(4, SIOCSIFNETMASK, {ifr_name="tun0", ifr_netmask={sa_family=AF_INET, sin_port=htons(8695), sin_addr=inet_addr("255.255.255.0")}}) = 0

            above seems to set a route, so: sudo route delete -net 10.0.8.0/24 tun0  will clear it.

        //set route
        sudo route add -net 10.0.8.0/24 tun0
            socket(AF_INET, SOCK_DGRAM, IPPROTO_IP) = 3
            ioctl(3, SIOCADDRT, 0x7ffea4766590)     = 0

        //show routing table
        route -n

        //delete a tun interface
        sudo ip link delete tun0


        //net-tools, show all interfaces including an unconfigured tun interface.
        ifconfig -a
    */


    /*
        https://stackoverflow.com/questions/6652384/how-to-set-the-ip-address-from-c-in-linux
        struct ifreq ifr;
        const char * name = "eth1";
        int fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);

        strncpy(ifr.ifr_name, name, IFNAMSIZ);

        ifr.ifr_addr.sa_family = AF_INET;
        inet_pton(AF_INET, "10.12.0.1", ifr.ifr_addr.sa_data + 2);
        ioctl(fd, SIOCSIFADDR, &ifr);

        inet_pton(AF_INET, "255.255.0.0", ifr.ifr_addr.sa_data + 2);
        ioctl(fd, SIOCSIFNETMASK, &ifr);

        ioctl(fd, SIOCGIFFLAGS, &ifr);
        strncpy(ifr.ifr_name, name, IFNAMSIZ);
        ifr.ifr_flags |= (IFF_UP | IFF_RUNNING);

        ioctl(fd, SIOCSIFFLAGS, &ifr);
    //        struct sockaddr_in* addr = (struct sockaddr_in*)&ifr.ifr_addr;
    //        inet_pton(AF_INET, "10.12.0.1", &addr->sin_addr);  //converts a string IP address to numeric binary

    */

    let task = Process()

    let outputPipe = Pipe()
    let errorPipe = Pipe()

    task.standardOutput = outputPipe
    task.standardError = errorPipe

    //FIXME: swap ifconfig with ip
    task.executableURL = URL(fileURLWithPath: "/sbin/ifconfig")

    task.arguments = [interfaceName, addressString, "netmask", subnetString]

    print("Setting \(interfaceName) address to \(addressString) netmask \(subnetString)")
    do {
        try task.run()
        task.waitUntilExit()
        print("done setting address")
    }
    catch {
        print("error setting address: \(error)")
        return true
    }

    let outputData = outputPipe.fileHandleForReading.readDataToEndOfFile()
    let errorData = errorPipe.fileHandleForReading.readDataToEndOfFile()

    let output = String(decoding: outputData, as: UTF8.self)
    let error = String(decoding: errorData, as: UTF8.self)

    if output != "" || error != "" {
        print("Output:\n\(output)\n")
        print("StdErr:\n\(error)\n")
    }

    return false
}


public func setAddressV6(interfaceName: String, addressString: String, subnetPrefix: UInt8) -> Bool
{
    //FIXME: should add input validation

    let task = Process()

    let outputPipe = Pipe()
    let errorPipe = Pipe()

    task.standardOutput = outputPipe
    task.standardError = errorPipe


    //ip -6 addr add fc00:bbbb:bbbb:bb01::1:b/64 dev tun0
    task.executableURL = URL(fileURLWithPath: "/sbin/ip")

    let CIDRAddress = addressString + "/" + subnetPrefix.string
    
    // -6: sets protocol family to inet6
    // addr: Shows addresses assigned to all network interfaces
    // add CIRAddress dev interfaceName: Add address (CIRAddress) to device (interfaceName)
    task.arguments = ["-6", "addr", "add", CIDRAddress, "dev", interfaceName]

    print("Setting \(interfaceName) address to \(addressString) netmask \(subnetPrefix)")
    do {
        try task.run()
        task.waitUntilExit()
        print("done setting address")
    }
    catch {
        print("error setting address: \(error)")
        return true
    }

    let outputData = outputPipe.fileHandleForReading.readDataToEndOfFile()
    let errorData = errorPipe.fileHandleForReading.readDataToEndOfFile()

    let output = String(decoding: outputData, as: UTF8.self)
    let error = String(decoding: errorData, as: UTF8.self)

    if output != "" || error != "" {
        print("Output:\n\(output)\n")
        print("StdErr:\n\(error)\n")
    }

    return false
}


public func setIPv6Forwarding(setTo: Bool) -> Bool
{
    // sysctl -w net.ipv6.conf.all.forwarding=1

    let task = Process()

    let outputPipe = Pipe()
    let errorPipe = Pipe()

    task.standardOutput = outputPipe
    task.standardError = errorPipe

    task.executableURL = URL(fileURLWithPath: "/sbin/sysctl")

    if setTo {
        print("enabling net.ipv6.conf.all.forwarding")
        
        // -w: write when all arguments prescribe a key to be set
        task.arguments = ["-w", "net.ipv6.conf.all.forwarding=1"]
    }
    else
    {
        print("disabling net.ipv6.conf.all.forwarding")
        
        // -w: write when all arguments prescribe a key to be set
        task.arguments = ["-w", "net.ipv6.conf.all.forwarding=0"]
    }

    do {
        try task.run()
        task.waitUntilExit()
        print("done ip_forward")
    }
    catch {
        print("ip_forward error: \(error)")
        return true
    }

    let outputData = outputPipe.fileHandleForReading.readDataToEndOfFile()
    let errorData = errorPipe.fileHandleForReading.readDataToEndOfFile()

    let output = String(decoding: outputData, as: UTF8.self)
    print(output)
    let error = String(decoding: errorData, as: UTF8.self)

    if error != "" {
        print("StdErr:\n\(error)\n")
    }

    return false
}


public func setIPv4Forwarding(setTo: Bool) -> Bool
{
    //set -- sysctl -w net.ipv4.ip_forward=1
    //get -- sysctl net.ipv4.ip_forward

    let task = Process()

    let outputPipe = Pipe()
    let errorPipe = Pipe()

    task.standardOutput = outputPipe
    task.standardError = errorPipe

    task.executableURL = URL(fileURLWithPath: "/sbin/sysctl")

    if setTo {
        print("enabling net.ipv4.ip_forward")
        
        // -w: write when all arguments prescribe a key to be set
        task.arguments = ["-w", "net.ipv4.ip_forward=1"]
    }
    else
    {
        print("disabling net.ipv4.ip_forward")
        
        // -w: write when all arguments prescribe a key to be set
        task.arguments = ["-w", "net.ipv4.ip_forward=0"]

    }

    do {
        try task.run()
        task.waitUntilExit()
        print("done ip_forward")
    }
    catch {
        print("ip_forward error: \(error)")
        return true
    }

    let outputData = outputPipe.fileHandleForReading.readDataToEndOfFile()
    let errorData = errorPipe.fileHandleForReading.readDataToEndOfFile()

    let output = String(decoding: outputData, as: UTF8.self)
    print(output)
    let error = String(decoding: errorData, as: UTF8.self)

    if error != "" {
        print("StdErr:\n\(error)\n")
    }

    return false
}


public func setClientRouteV6(destinationAddress: String, gatewayAddress: String, interfaceName: String) -> Bool
{
    //FIXME: add input checking

    //sudo ip -6 route add fe80::f97e:48da:d889:cb22 dev tun0
    //ip -6 route add default dev eth0 metric 1

    let task = Process()

    let outputPipe = Pipe()
    let errorPipe = Pipe()

    task.standardOutput = outputPipe
    task.standardError = errorPipe

    task.executableURL = URL(fileURLWithPath: "/usr/sbin/ip")

    // -6: sets protocol family to inet6
    // route: List all of the route entries in the kernel
    // add destinationAddress dev interfaceName: Add address (destinationAddress) to device (interfaceName)
    // metric 1: sets the metric(cost) of the operation
    task.arguments = ["-6", "route", "add", destinationAddress, "dev", interfaceName, "metric", "1"]

    do {
        try task.run()
        task.waitUntilExit()
        print("done set client route")
    }
    catch {
        print("error setting client route: \(error)")
        return true
    }

    let outputData = outputPipe.fileHandleForReading.readDataToEndOfFile()
    let errorData = errorPipe.fileHandleForReading.readDataToEndOfFile()

    let output = String(decoding: outputData, as: UTF8.self)
    print("set default ipv6 route output: \(output)")
    let error = String(decoding: errorData, as: UTF8.self)

    if error != "" {
        print("Output:\n\(output)\n")
        print("Error setting default ipv6 route output:\n\(error)\n")
    }

    return false
}

public func setClientRoute(destinationAddress: String, gatewayAddress: String, interfaceName: String) -> Bool
{
    //set -- route add default gw 10.4.2.5 tun0
    //get -- netstat -r

    //sudo ip -6 route add fe80::f97e:48da:d889:cb22 dev tun0


    //FIXME: in routing.swift, add function to set route allowing traffic to vpn server to go over the internet connected interface:
    //route add 143.110.154.116 gw 10.211.55.1 enp0s5


    let task = Process()

    let outputPipe = Pipe()
    let errorPipe = Pipe()

    task.standardOutput = outputPipe
    task.standardError = errorPipe

    //FIXME: change route command to ip  command
    task.executableURL = URL(fileURLWithPath: "/sbin/route")

    // add: add a route (destinationAddress)
    // gw: assign a gateway address
    task.arguments = ["add", destinationAddress, "gw", gatewayAddress, interfaceName]

    do {
        try task.run()
        task.waitUntilExit()
        print("done set client route")
    }
    catch {
        print("error setting client route: \(error)")
        return true
    }

    let outputData = outputPipe.fileHandleForReading.readDataToEndOfFile()
    let errorData = errorPipe.fileHandleForReading.readDataToEndOfFile()

    let output = String(decoding: outputData, as: UTF8.self)
    print("set default route output: \(output)")
    let error = String(decoding: errorData, as: UTF8.self)

    if error != "" {
        print("Output:\n\(output)\n")
        print("StdErr:\n\(error)\n")
    }

    return false
}


public func getNATv6() -> String
{
    let task = Process()

    let outputPipe = Pipe()
    let errorPipe = Pipe()

    task.standardOutput = outputPipe
    task.standardError = errorPipe

    task.executableURL = URL(fileURLWithPath: "/sbin/ip6tables")

    // -t (table): use (NAT) table [prerouting, output, postrouting]
    // -n: --numeric: print IP and port in numeric format
    // -L: list all rules in the selected chain
    // -v: --verbose: make list command show the interface name, rule options, and TOS masks
    task.arguments = ["-t", "nat", "-n", "-L", "-v"]

    do {
        try task.run()
        task.waitUntilExit()
        print("done get nat")
    }
    catch {
        print("get nat error: \(error)")
        return "error"
    }

    let outputData = outputPipe.fileHandleForReading.readDataToEndOfFile()
    let errorData = errorPipe.fileHandleForReading.readDataToEndOfFile()

    let output = String(decoding: outputData, as: UTF8.self)
    //print("iptables NAT config output: \(output)")
    let error = String(decoding: errorData, as: UTF8.self)

    if error != "" {

        print("StdErr:\n\(error)\n")
    }

    return output
}


public func getNAT() -> String
{
    let task = Process()

    let outputPipe = Pipe()
    let errorPipe = Pipe()

    task.standardOutput = outputPipe
    task.standardError = errorPipe

    task.executableURL = URL(fileURLWithPath: "/usr/sbin/iptables")

    // -t (table): use (NAT) table [prerouting, output, postrouting]
    // -n: --numeric: print IP and port in numeric format
    // -L: list all rules in the selected chain
    // -v: --verbose: make list command show the interface name, rule options, and TOS masks
    task.arguments = ["-t", "nat", "-n", "-L", "-v"]

    do {
        try task.run()
        task.waitUntilExit()
        print("done get nat")
    }
    catch {
        print("get nat error: \(error)")
        return "error"
    }

    let outputData = outputPipe.fileHandleForReading.readDataToEndOfFile()
    let errorData = errorPipe.fileHandleForReading.readDataToEndOfFile()

    let output = String(decoding: outputData, as: UTF8.self)
    //print("iptables NAT config output: \(output)")
    let error = String(decoding: errorData, as: UTF8.self)

    if error != "" {

        print("StdErr:\n\(error)\n")
    }

    return output
}


public func deleteServerNATv6(serverPublicInterface: String) -> Bool
{
    //ip6tables -t nat -D POSTROUTING -o eth0 -j MASQUERADE
    let task = Process()

    let outputPipe = Pipe()
    let errorPipe = Pipe()

    task.standardOutput = outputPipe
    task.standardError = errorPipe

    task.executableURL = URL(fileURLWithPath: "/usr/sbin/ip6tables")
    
    // -t (table): use (NAT) table [prerouting, output, postrouting]
    // -D: --delete (chain) (rulenum/rule-specification): delete one or more rules (-j MASQUERADE -o serverPublicInterface) from the selected chain (POSTROUTING)
    // -j: --jump (target): Specify what to do if the packet matches (MASQUERADE)
    // -o: --out-interface (name): Name of an interface via which a packet is going to be sent (serverPublicInterface)
    task.arguments = ["-t", "nat", "-D", "POSTROUTING", "-j", "MASQUERADE", "-o", serverPublicInterface]

    do {
        try task.run()
        task.waitUntilExit()
        print("done delete nat")
    }
    catch {
        print("error deleting nat: \(error)")
        return true
    }

    _ = outputPipe.fileHandleForReading.readDataToEndOfFile()
    let errorData = errorPipe.fileHandleForReading.readDataToEndOfFile()

    //let output = String(decoding: outputData, as: UTF8.self)
    //print("iptables NAT config output: \(output)")
    let error = String(decoding: errorData, as: UTF8.self)

    if error != "" {
        //print("StdErr:\n\(error)\n")
        return true
    }

    return false
}


public func deleteServerNAT(serverPublicInterface: String) -> Bool
{
    let task = Process()

    let outputPipe = Pipe()
    let errorPipe = Pipe()

    task.standardOutput = outputPipe
    task.standardError = errorPipe

    task.executableURL = URL(fileURLWithPath: "/usr/sbin/iptables")
    
    // -t (table): use (NAT) table [prerouting, output, postrouting]
    // -D: --delete (chain) (rulenum/rule-specification): delete one or more rules (-j MASQUERADE -o serverPublicInterface) from the selected chain (POSTROUTING)
    // -j: --jump (target): Specify what to do if the packet matches (MASQUERADE)
    // -o: --out-interface (name): Name of an interface via which a packet is going to be sent (serverPublicInterface)
    task.arguments = ["-t", "nat", "-D", "POSTROUTING", "-j", "MASQUERADE", "-o", serverPublicInterface]

    do {
        try task.run()
        task.waitUntilExit()
        print("done delete nat")
    }
    catch {
        print("error deleting server NAT: \(error)")
        return false
    }

    _ = outputPipe.fileHandleForReading.readDataToEndOfFile()
    let errorData = errorPipe.fileHandleForReading.readDataToEndOfFile()

    //let output = String(decoding: outputData, as: UTF8.self)
    //print("iptables NAT config output: \(output)")
    let error = String(decoding: errorData, as: UTF8.self)

    if error != "" {
        //print("StdErr:\n\(error)\n")
        return false
    }

    return true
}


public func configServerNATv6(serverPublicInterface: String) -> Bool
{
    //add rule ipv6: ip6tables -t nat -A POSTROUTING -o enp0s5 -j MASQUERADE

    let task = Process()

    let outputPipe = Pipe()
    let errorPipe = Pipe()

    task.standardOutput = outputPipe
    task.standardError = errorPipe

    task.executableURL = URL(fileURLWithPath: "/sbin/ip6tables")

    //print("enabling NAT for \(serverPublicInterface)")
    //print("enabling NAT for \(serverPublicInterface)")
    // -t (table): use (NAT) table [prerouting, output, postrouting]
    // -A: --append (chain) (rule-specification): Append one or more rules(-j MASQUERADE -o serverPublicInterface) to the end of the selected chain(POSTROUTING)
    // -j: --jump (target): Specify what to do if the packet matches (MASQUERADE)
    // -o: --out-interface (name): Name of an interface via which a packet is going to be sent (serverPublicInterface)
    task.arguments = ["-t", "nat", "-A", "POSTROUTING", "-j", "MASQUERADE", "-o", serverPublicInterface ]

    do {
        try task.run()
        task.waitUntilExit()
        print("done config nat")
    }
    catch {
        print("error deleting server NAT: \(error)")
        return true
    }

    _ = outputPipe.fileHandleForReading.readDataToEndOfFile()
    let errorData = errorPipe.fileHandleForReading.readDataToEndOfFile()

    //let output = String(decoding: outputData, as: UTF8.self)
    //print("iptables NAT config output: \(output)")
    let error = String(decoding: errorData, as: UTF8.self)

    if error != "" {
        print("StdErr:\n\(error)\n")
    }

    return false
}


public func configServerNAT(serverPublicInterface: String) -> Bool
{
    //add rule -- iptables -t nat -A POSTROUTING -j MASQUERADE -o enp0s5
    //delete rule -- iptables -t nat -D POSTROUTING -j MASQUERADE -o enp0s5
    //show current NAT -- iptables -t nat -n -L -v

    let task = Process()

    let outputPipe = Pipe()
    let errorPipe = Pipe()

    task.standardOutput = outputPipe
    task.standardError = errorPipe

    task.executableURL = URL(fileURLWithPath: "/usr/sbin/iptables")

    //print("enabling NAT for \(serverPublicInterface)")
    // -t (table): use (NAT) table [prerouting, output, postrouting]
    // -A: --append (chain) (rule-specification): Append one or more rules(-j MASQUERADE -o serverPublicInterface) to the end of the selected chain(POSTROUTING)
    // -j: --jump (target): Specify what to do if the packet matches (MASQUERADE)
    // -o: --out-interface (name): Name of an interface via which a packet is going to be sent (serverPublicInterface)
    // iptables -t nat -A POSTROUTING -s 10.200.200.0/24 -o eth0 -j MASQUERADE
    task.arguments = ["-t", "nat", "-A", "POSTROUTING", "-s", "10.8.0.0/24", "-j", "MASQUERADE", "-o", serverPublicInterface ]

    do {
        try task.run()
        task.waitUntilExit()
        print("done config nat")
    }
    catch {
        print("nat config error: \(error)")
        return true
    }

    _ = outputPipe.fileHandleForReading.readDataToEndOfFile()
    let errorData = errorPipe.fileHandleForReading.readDataToEndOfFile()

    //let output = String(decoding: outputData, as: UTF8.self)
    //print("iptables NAT config output: \(output)")
    let error = String(decoding: errorData, as: UTF8.self)

    if error != "" {
        print("StdErr:\n\(error)\n")
    }

    return false
}

public func setDNS()
{
    //FIXME:  add function(s) to set name servers / DNS servers
}


public func setMTU(interface: String, mtu: Int) -> Bool
{
    //ifconfig enp0s6 mtu 1380

    if mtu > 1600 || mtu < 128
    {
        print("mtu out of bounds")
        return true
    }

    let task = Process()

    let outputPipe = Pipe()
    let errorPipe = Pipe()

    task.standardOutput = outputPipe
    task.standardError = errorPipe

    task.executableURL = URL(fileURLWithPath: "/sbin/ifconfig")

    //print("enabling NAT for \(serverPublicInterface)")
    task.arguments = [  interface, "mtu", mtu.string ]

    do {
        try task.run()
        task.waitUntilExit()
        print("done setting mtu to \(mtu.string)")
    }
    catch {
        print("error setting mtu: \(error)")
        return true
    }

    _ = outputPipe.fileHandleForReading.readDataToEndOfFile()
    let errorData = errorPipe.fileHandleForReading.readDataToEndOfFile()

    //let output = String(decoding: outputData, as: UTF8.self)
    let error = String(decoding: errorData, as: UTF8.self)

    if error != "" {
        print("StdErr:\n\(error)\n")
    }

    return false

}

