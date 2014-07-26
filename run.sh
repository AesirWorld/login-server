#!/bin/sh
pkill global-server
go build

clean_up() {
    rm global-server
}

trap clean_up SIGINT

if [ $? -eq 0 ]; then
    ./global-server 
fi
