"""Run the project's four-host OpenFlow 1.3 network with a remote controller."""

from mininet.cli import CLI
from mininet.log import setLogLevel
from mininet.net import Mininet
from mininet.node import OVSSwitch, RemoteController
from mininet.topo import Topo


def main():
    topology = Topo()
    switch = topology.addSwitch("s1", protocols="OpenFlow13")
    host_addresses = (
        ("h1", "10.0.0.1/24"),
        ("h2", "10.0.0.2/24"),
        ("h3", "10.0.0.3/24"),
        ("h4", "10.0.0.10/24"),
    )
    for switch_port, (name, address) in enumerate(host_addresses, start=1):
        host = topology.addHost(name, ip=address)
        topology.addLink(host, switch, port1=0, port2=switch_port)

    # Build inside the try block so partial startup also reaches cleanup.
    network = Mininet(
        topo=topology, controller=None, switch=OVSSwitch, build=False
    )
    try:
        network.addController(
            "c0", controller=RemoteController, ip="127.0.0.1", port=6653
        )
        network.build()
        network.start()
        CLI(network)
    finally:
        network.stop()


if __name__ == "__main__":
    setLogLevel("info")
    try:
        main()
    except KeyboardInterrupt:
        pass
