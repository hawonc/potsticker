#!/bin/bash

# Run docker-compose commands
docker compose build
docker compose stop
docker compose start
