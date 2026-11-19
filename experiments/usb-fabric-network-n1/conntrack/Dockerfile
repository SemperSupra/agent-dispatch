FROM ubuntu:24.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update -qq && apt-get install -y -qq --no-install-recommends \
 nftables iproute2 python3 && rm -rf /var/lib/apt/lists/*
COPY experiments/usb-fabric-network-n1/conntrack/check.py /opt/n3/check.py
COPY experiments/usb-fabric-network-n1/conntrack/run.sh /opt/n3/run.sh
ENV USB_NET_DISPOSABLE=YES
ENTRYPOINT ["/bin/sh","/opt/n3/run.sh"]
