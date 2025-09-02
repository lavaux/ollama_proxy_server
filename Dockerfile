FROM python:3.11

ARG VER=0.1.0
# Update packagtes, install necessary tools into the base image, clean up and clone git repository
RUN apt update \
    && apt install -y --no-install-recommends --no-install-suggests git apache2 \
    && apt autoremove -y --purge \
    && apt clean \
    && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/* \
    && git clone https://github.com/lavaux/ollama_proxy_server.git \
    && git checkout v$VER \
    && mv ollama_proxy_server /app

# Change working directory to cloned git repository
WORKDIR /app

# Install all needed requirements
RUN pip3 install --no-cache-dir -e .

# Copy config.ini and authorized_users.txt into project working directory
#COPY config.ini .
#COPY authorized_users.txt .

# Start the proxy server as entrypoint
ENTRYPOINT ["ollama_proxy_server"]

# Do not buffer output, e.g. logs to stdout
ENV PYTHONUNBUFFERED=1

# Set command line parameters
CMD ["--config", "/config/config.ini", "--users_list", "/config/authorized_users.txt", "--port", "8080"]
