FROM zeek/zeek:6.0.3

# Install build essentials, development libraries, and git for compiling Spicy plugins
RUN apt-get update && apt-get install -y \
    build-essential \
    cmake \
    g++ \
    git \
    libcap2-bin \
    libpcap-dev \
    libssl-dev \
    python3-pip \
    zlib1g-dev \
    && rm -rf /var/lib/apt/lists/*

# Configure zkg, skip tests, and install ICSNPP plugins
RUN zkg autoconfig --force && \
    echo y | zkg install --skiptests icsnpp-modbus && \
    echo y | zkg install --skiptests icsnpp-s7comm && \
    echo y | zkg install --skiptests icsnpp-enip && \
    echo y | zkg install --skiptests icsnpp-dnp3

# Setup capture user privileges
RUN useradd --system --no-create-home --shell /usr/sbin/nologin zeekcap \
    && setcap cap_net_raw,cap_net_admin=eip /usr/local/zeek/bin/zeek

COPY local.zeek /usr/local/zeek/share/zeek/site/local.zeek
WORKDIR /usr/local/zeek
ENTRYPOINT ["/usr/local/zeek/bin/zeek"]