# Routing

Swift project that provides methods to change network interface routing parameters.   

Currently only Linux is supported. Tested on Ubuntu 18.04.   

For IPv4 and IPv6 the following are implemented:   
* Set route, address, NAT   
* Get route, NAT   
* Delete NAT   
* Enable/Disable IP forwarding   

To do (including but not limited to):   
* //FIXME: move/add input validation from TunTesterCli to TunDevice   
* //FIXME: change to ioctls?   
* //FIXME: add get functionality for address, IP forwarding, route   
* //FIXME: change get functions to return structs instead of a string to make checking settings easier   
* //FIXME: add remove address functionality   
* //FIXME: add DNS functionality   
* //FIXME: add MacOS support   
* //FIXME: make more generic/universal   
* //FIXME: write tests   
