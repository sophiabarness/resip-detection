Honeygain packet capture setup:

(0) (optional) if running on Mac, install `multipass` for easily running shell-only vms.

```
brew install multipass
multipass launch --name test-vm
multipass shell test-vm
```

(1) In linux, install docker following the recommended installation

(2) In linux, with docker installed, run the honeygain app using:

```
docker run honeygain/honeygain -tou-accept -email <EMAIL>  -pass<PASS> -device multipass
```

This will start the docker container that proxies all traffic.

(3) In linux, in a separate shell, start tcpdump _just for that container_ using nsenter. Honeygain only has one process, so it’s safe to capture all traffic.

```
docker ls # get all running containers
docker inspect --format '{{.State.Pid}}' <container-name-or-id> # get the PID for the server
sudo nsenter -t <PID> -n tcpdump -i any -nn -tt -s 256 -C 100 -W 5 -w /tmp/capture.pcap
```

(4) (optional) If running on Mac, copy the data back to Mac using `multipass transfer test-vm/tmp/capture.pcap* ~/Desktop`

(5) Read resulting pcap files using tcpdump or wireshark

(6) Merge all files from a provider into one, e.g., mergecap -w honeygain.pcap capture.pcap0 capture.pcap1 capture.pcap2 capture.pcap3

(7) run analysis, e.g., python analyze_pcap.py --pcap honeygain.pcap
