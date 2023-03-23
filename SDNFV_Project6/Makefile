all:
	sudo docker compose up -d
	sudo ovs-vsctl add-br ovsbr0
	sudo ip addr add dev ovsbr0 172.20.0.0/16
	sudo ip link set dev ovsbr0 up
	sudo ovs-vsctl set bridge ovsbr0 protocols=OpenFlow14
	sudo ovs-vsctl set-controller ovsbr0 tcp:127.0.0.1:6653
	sudo ovs-docker add-port ovsbr0 eth4 R1 --ipaddress=172.20.0.2/16
	sudo ovs-docker add-port ovsbr0 eth4 R2 --ipaddress=172.20.0.3/16
	sudo ovs-docker add-port ovsbr0 eth4 R3 --ipaddress=172.20.0.4/16

clean:
	sudo docker compose down
	sudo ovs-vsctl del-br ovsbr0