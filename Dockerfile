from 32bit/ubuntu:16.04
RUN apt-get update -y
RUN apt-get install nasm -y 
RUN apt-get install build-essential -y 
RUN mkdir ./RV
COPY ./ ./RV
WORKDIR ./RV
RUN make 
RUN ./rv
RUN ./test
RUN sleep 1000

