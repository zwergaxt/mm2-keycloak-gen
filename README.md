# General
A small python script to init role model in Keycloak for Kafka MirrorMaker2 auth

## Objects created in Keycloak
Based on config file (./config/config.cfg) there are sveral objects created in Keycloak:
- Client
- Resources in Kafka client
- Policies in Kafka client
- Permissions on Kafka client

Basic set of scopes applied to Resources objects of source and destination clusters:
kafka-cluster:<config.project_id>:Cluster - describe, describeConfigs
kafka-cluster:<config.project_id>:Group - read, describe, write, create, describeConfigs
kafka-cluster:<config.project_id>:Topic - describe, describeConfigs

# Basic config
```
[manager]
url = http://keycloak.local
client = manager
client_key = 3feE6bm1OgvtgAgkfS42cAYdEmBqdaQv

[resources]
kafka_client_name = kafka1
project_id = project-consumer2,project-producer2

[client_config]
target_client = client-mm2
```

**url** - Keycloak URL  
**client** - client witch admin privileges  
**client_key** - secret of client  
**kafka_client_name** - ClientId of Kafka client  
**project_id** - name on Kafka clusters  
**target_client** - client that will be created for replication  

# Usage
docker run --mount type=bind,src="./config",dst="/app/config/" --network host keycloak-api:latest