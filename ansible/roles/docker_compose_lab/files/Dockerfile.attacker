FROM kalilinux/kali-rolling:latest

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get upgrade -y && \
    apt-get install -y --no-install-recommends \
      vim \
      nmap \
      jq \
      metasploit-framework \
      netcat-traditional \
      telnet \
      smbclient \
      redis-tools \
      python3-pip \
      python3-venv \
      curl \
      wget \
      python3 \
      awscli \
      openssh-client \
      hydra \
      python2.7 \
      python2.7-dev \
      git \
      gcc \
      file \
      openjdk-11-jre \
      iputils-ping \
      iproute2 \
    && apt-get autoremove -y \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

CMD ["sleep", "infinity"]
