FROM ubuntu:18.04
MAINTAINER Simon Fraser <sfraser@mozilla.com>

# Required software
ENV DEBIAN_FRONTEND noninteractive
# Chain apt-get commands with apt-get clean in a single docker RUN
# to make sure that files are removed within a single docker layer
RUN apt-get update -q && \
    apt-get install -yyq --no-install-recommends \
    python3.6 python3-setuptools python3-cryptography libgetopt-simple-perl \
    bzip2 clamav clamav-freshclam python3-requests python3-sh curl \
    python3-dev gcc liblzma-dev xz-utils jq libdpkg-perl locales && \
    apt-get clean
RUN useradd -d /home/worker -s /bin/bash -m worker
COPY requirements.txt /tmp/

RUN locale-gen en_CA.UTF-8
ENV LANG en_CA.UTF-8
ENV LANGUAGE en_CA.UTF-8
ENV LANG_ALL en_CA.UTF-8
ENV LC_ALL en_CA.UTF-8

# Freshclam may be flaky, retry if it fails
RUN for i in 1 2 3 4 5; do freshclam --verbose && break || sleep 15; done

# python-pip installs a lot of dependencies increasing the size of an image
# drastically. Install it like this saves us almost 200M.
RUN bash -c "curl -L https://bootstrap.pypa.io/get-pip.py | python3"
RUN pip install -r /tmp/requirements.txt

# scripts
RUN mkdir /home/worker/bin
COPY scripts/* /home/worker/bin/

COPY runme.sh /runme.sh
COPY recompress.sh /recompress.sh
RUN chmod 755 /home/worker/bin/* /*.sh
RUN mkdir /home/worker/keys
COPY *.pubkey /home/worker/keys/

ENV           HOME          /home/worker
ENV           SHELL         /bin/bash
ENV           USER          worker
ENV           LOGNAME       worker

CMD ["/runme.sh"]
