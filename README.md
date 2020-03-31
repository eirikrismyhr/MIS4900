MIS4900 - Master Thesis Project

Command to capture live traffic and save to file:
sudo tshark -i wlp7s0 -f "src port 53" -w /home/eirik/Master/MIS4900/dns-local.pcap
