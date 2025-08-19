# General

A small python scrip to create role model in Keycloak for Kafka MirrorMaker2 auth

# Usage

docker run --mount type=bind,src="./config",dst="/app/config/" --network host keycloak-api:latest