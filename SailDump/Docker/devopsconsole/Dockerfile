FROM nginx:latest

RUN apt-get update && \
  apt-get -y upgrade && \
  apt-get install -y python3-pip

COPY requirements.txt requirements.txt
RUN pip3 install -r requirements.txt

COPY Entrypoint.sh /Entrypoint.sh
RUN chmod +x Entrypoint.sh

CMD ["/bin/bash", "/Entrypoint.sh"]
