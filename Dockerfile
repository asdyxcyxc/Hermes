FROM ubuntu:18.04

WORKDIR /app/

RUN apt-get update -qq

RUN apt-get  install -y libpcap-dev build-essential

COPY . /app/

RUN cd afl-2.52b/ && make && make install && cd -

RUN cd afl-protocol && make && cd -

RUN cd sample/simple && CC=afl-gcc make && mkdir -p input_dir && cd -

RUN chmod +x ./entrypoint.sh

RUN rm -rf .git

ENTRYPOINT [ "./entrypoint.sh" ]
