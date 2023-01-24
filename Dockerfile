FROM golang:latest

RUN mkdir /app
COPY . /app

WORKDIR /app
RUN make

EXPOSE 9903

CMD ["./ipsec_exporter"]
