FROM ubuntu:20.04

ARG AZURE_SUBSCRIPTION_ID=${AZURE_SUBSCRIPTION_ID}
ENV AZURE_SUBSCRIPTION_ID=${AZURE_SUBSCRIPTION_ID}
ARG AZURE_TENANT_ID=${AZURE_TENANT_ID}
ENV AZURE_TENANT_ID=${AZURE_TENANT_ID}
ARG AZURE_CLIENT_ID=${AZURE_CLIENT_ID}
ENV AZURE_CLIENT_ID=${AZURE_CLIENT_ID}
ARG AZURE_CLIENT_SECRET=${AZURE_CLIENT_SECRET}
ENV AZURE_CLIENT_SECRET=${AZURE_CLIENT_SECRET}

# Install dependencies
RUN apt-get update && \
  apt-get -y upgrade && \
  apt-get install -y \
  sudo \
  libcurl4-gnutls-dev \
  libcurl4 \
  libssl-dev \
  libuuid1 \
  python3-pip && \
  rm -rf /var/lib/apt/lists/*

COPY requirements.txt /requirements.txt
RUN pip3 install -r requirements.txt

COPY Entrypoint.sh /Entrypoint.sh
RUN AZURE_SUBSCRIPTION_ID=$AZURE_SUBSCRIPTION_ID \
  AZURE_TENANT_ID=$AZURE_TENANT_ID \
  AZURE_CLIENT_ID=$AZURE_CLIENT_ID \
  AZURE_CLIENT_SECRET=$AZURE_CLIENT_SECRET
RUN chmod +x /Entrypoint.sh

CMD ["/bin/bash", "/Entrypoint.sh"]
