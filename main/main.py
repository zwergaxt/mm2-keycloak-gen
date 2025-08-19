import configparser
import traceback
import logging
import uuid
from keycloak import KeycloakAdmin, KeycloakOpenIDConnection, KeycloakError

# Base logger config
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


def read_config():
    config = configparser.ConfigParser()
    config.read(r"/app/config/config.cfg")

    keycloak_config = dict(config.items("manager"))
    keycloak_config["resources"] = dict(config.items("resources"))
    keycloak_config["client_config"] = dict(config.items("client_config"))

    return keycloak_config


def connect_to_keycloak(config: dict):
    """
    Create admin connection to Keycloak

    config example:
        [manager]
        url = http://keycloak.local/
        client = manager
        client_key = secret

    :config: connection settings
    """
    try:
        connection = KeycloakOpenIDConnection(
            server_url=config["url"],
            realm_name="kafka-authz",
            client_id=config["client"],
            client_secret_key=config["client_key"],
            verify=False,
        )

        admin = KeycloakAdmin(connection=connection)

        if len(admin.get_clients()) > 0:
            logger.info("Connection success")

        return admin

    except Exception:
        logger.error("Error occured when creating connection to Keycloak")
        logger.error(traceback.format_exc().splitlines()[-1])


def check_keycloak_client(payload: dict, admin_connection: KeycloakAdmin):
    """
    Check existance of client with given parameters.

    :payload: client names
    :admin_connection: admin connection
    """
    client_set = []

    config_list = [item.strip() for item in payload["target_client"].split(",")]

    try:
        clients = admin_connection.get_clients()
    except Exception:
        logger.error("Error occured when checking Client")
        logger.error(traceback.format_exc().splitlines()[-1])

    for i in config_list:
        client_set.append(next((sub for sub in clients if sub["clientId"] == i), None))

    return client_set


def create_keycloak_client(payload: dict, admin_connection: KeycloakAdmin):
    """
    Create client with given parameters.

    payload example:
        client_config = {
                "clientId": i,
                "name": i,
                "protocol": "openid-connect",
                "clientAuthenticatorType": "client-secret",
                "secret": "test-secret",
                "serviceAccountsEnabled": "true",
                "directAccessGrantsEnabled": "true",
                "publicClient": "false",
            }

    :payload: client names
    :admin_connection: admin connection
    """

    client_set = []
    config_list = [item.strip() for item in payload["target_client"].split(",")]

    logger.info(f"New clients {config_list} will be created")

    for i in config_list:
        logger.info(f"Creating client {i}")

        client_config = {
            "clientId": i,
            "name": i,
            "protocol": "openid-connect",
            "clientAuthenticatorType": "client-secret",
            "secret": "test-secret",
            "serviceAccountsEnabled": "true",
            "directAccessGrantsEnabled": "true",
            "publicClient": "false",
        }

        try:
            new_client = admin_connection.create_client(
                payload=client_config, skip_exists=False
            )

            logger.info(f"Client with ID {new_client} created!")

            client_set.append(new_client)

        except KeycloakError as e:
            search_string = "already exists"
            if search_string in e.error_message.decode():
                logging.warning(
                    "Seems like clients already exist. Trying to find them!"
                )
                for i in config_list:
                    logging.warning(f"Searching client {i}")
                    client_set.append(
                        get_keycloak_client_by_name(
                            admin_connection=admin_connection,
                            client_name=i,
                            get_scopes=False,
                        )["id"]
                    )

        except Exception:
            logger.error("Error occured when creating Client")
            logger.error(traceback.format_exc().splitlines()[-1])

    return client_set


def get_keycloak_client(admin_connection: KeycloakAdmin, client_id):
    """
    Get keycloak client by id name

    :admin_connection: admin connection
    :client_id: id of client to search for
    """
    try:
        client = admin_connection.get_client(client_id=client_id)
        # client["scopes"] = admin_connection.get_client_authz_scopes(client_id=client_id)

        return client
    except Exception:
        logger.error(f"Error occured when getting {client_id} Client")
        logger.error(traceback.format_exc().splitlines()[-1])


def get_keycloak_client_by_name(
    admin_connection: KeycloakAdmin, client_name, get_scopes: bool
):
    """
    Get keycloak client id by given name

    :param admin_connection: admin connection
    :type admin_connection: KeycloakAdmin
    :param client_name: name of client to search for
    : type client_name: str
    :param get_scopes: get associated scopes
    :type get_scopes: bool

    :return: keycloak client
    :rtype: dict
    """
    try:
        clients = admin_connection.get_clients()
        kafka_client = list(filter(lambda x: x["clientId"] == client_name, clients))

        if len(kafka_client) > 0:
            kafka_client_id = kafka_client[0]["id"]
            client = admin_connection.get_client(kafka_client_id)
            if get_scopes == True:
                client["scopes"] = admin_connection.get_client_authz_scopes(
                    client_id=kafka_client_id
                )
        else:
            raise ValueError(f"Client with name {client_name} not found")

        return client

    except Exception:
        logger.error(f"Error occured when getting {client_name} Client")
        logger.error(traceback.format_exc().splitlines()[-1])


def get_client_resources_dict(admin_connection: KeycloakAdmin, kafka_client):
    resource_set = {}

    try:
        resources = admin_connection.get_client_authz_resources(client_id=kafka_client)
    except Exception:
        logger.error(f"Error occured when getting client data")
        logger.error(traceback.format_exc().splitlines()[-1])

    for i in resources:
        resource_set[i["name"]] = i["_id"]

    return resource_set


def get_client_policies_dict(admin_connection: KeycloakAdmin, kafka_client):
    policies_set = {}

    try:
        policies = admin_connection.get_client_authz_policies(client_id=kafka_client)
    except Exception:
        logger.error(f"Error occured when getting client data")
        logger.error(traceback.format_exc().splitlines()[-1])

    for i in policies:
        policies_set[i["name"]] = i["id"]

    return policies_set


def get_client_permissions_dict(admin_connection: KeycloakAdmin, kafka_client):
    permissions_set = {}

    try:
        permissions = admin_connection.get_client_authz_permissions(
            client_id=kafka_client
        )
    except Exception:
        logger.error(f"Error occured when getting client data")
        logger.error(traceback.format_exc().splitlines()[-1])

    for i in permissions:
        permissions_set[i["name"]] = i["id"]

    return permissions_set


def create_keycloak_resource(
    admin_connection: KeycloakAdmin, kafka_client, payload: dict
):
    """
    Creates keycloak resource

    :admin_connection: admin connection
    :client_id: id of parent client for resource e.g. kafka
    :payload: config which contains kafka cluster names
    """
    resource_set = []
    config_list = [
        item.strip() for item in payload["resources"]["project_id"].split(",")
    ]

    client = get_keycloak_client_by_name(
        admin_connection=admin_connection, client_name=kafka_client, get_scopes=True
    )

    client_resources = get_client_resources_dict(admin_connection, client["id"])

    for r in ["Cluster", "Group", "Topic"]:
        for i in config_list:
            resource_config = {
                "name": f"kafka-cluster:{i},{r}:*",
                "displayName": i,
                "scopes": client["scopes"],
                "type": r,
            }

            logger.info(f"Creating resource {resource_config["name"]}")

            if resource_config["name"] in client_resources:
                logger.warning(f"Resource {resource_config["name"]} already exists")
                resource_set.append(
                    client_resources.get(resource_config["name"])
                    )
            else:
                try:
                    new_resource = admin_connection.create_client_authz_resource(
                        client_id=client["id"],
                        payload=resource_config,
                        skip_exists=False,
                    )

                    resource_set.append(new_resource["_id"])

                    logger.info(f"Resource with ID {new_resource["name"]} created!")

                except Exception:
                    logger.error("Error occured when creating Resource")
                    logger.error(traceback.format_exc().splitlines()[-1])

    return resource_set


def create_keycloak_group_policy(admin_connection: KeycloakAdmin, kafka_client, group):
    kafka_client = get_keycloak_client_by_name(
        admin_connection=admin_connection, client_name=kafka_client, get_scopes=True
    )

    try:
        group_id = admin_connection.get_group_by_path(group)

        if group_id.get("error"):
            raise ValueError(
                f"Error occured when getting group {group}.\n {group_id.get('error')}"
            )
        else:
            print(group_id)

    except Exception:
        logger.error(f"Error occured when getting group {group}")
        logger.error(traceback.format_exc().splitlines()[-1])

    policy_config = {
        "name": group,
        "type": "group",
        "logic": "POSITIVE",
        "decisionStrategy": "UNANIMOUS",
        "groups": {"id": group_id["id"], "extendChildren": "false"},
    }

    try:
        admin_connection.create_client_authz_policy(
            client_id=kafka_client["id"], payload=policy_config, skip_exists=False
        )
    except Exception:
        logger.error(f"Error occured when creating group policy for {group}")
        logger.error(traceback.format_exc().splitlines()[-1])


def create_keycloak_client_policy(
    admin_connection: KeycloakAdmin, kafka_client, target_client: list
):
    """
    Create client policy in keycloak

    :param admin_connection: admin connection
    :type admin_connection: KeycloakAdmin
    :param kafka_client: name of central kafka client e.g. kafka
    :type kafka_client: str
    :param target_client: list of clients to include in policies
    :type target_client: list

    :return: Created policy id
    :rtype: list
    """
    policy_set = []
    target_client_full = []

    client = get_keycloak_client_by_name(
        admin_connection=admin_connection, client_name=kafka_client, get_scopes=True
    )

    client_policies = get_client_policies_dict(admin_connection, client["id"])

    for i in target_client:
        target_client_full.append(get_keycloak_client(
            admin_connection=admin_connection, client_id=i
        ))

    for i in target_client_full:
        logger.info(f"Creating client policy for client with id {i["clientId"]}")


        policy_config = {
            "name": f"Client:{i["clientId"]}",
            "type": "client",
            "logic": "POSITIVE",
            # "decisionStrategy": "UNANIMOUS",
            "clients": [i["id"]],
        }

        if policy_config["name"] in client_policies:
            logger.warning(f"Policy {policy_config["name"]} already exists")
            policy_set.append(client_policies.get(policy_config["name"]))
        else:
            try:
                policy = admin_connection.create_client_authz_client_policy(
                    client_id=client["id"], payload=policy_config
                )

                logging.info(f"Policy with id {policy['name']} created")

                policy_set.append(policy["id"])
            except Exception:
                logger.error(
                    f"Error occured when creating client policy for {i["clientId"]}"
                )
                logger.error(traceback.format_exc().splitlines()[-1])

    return policy_set


def create_keycloak_permissions(
    admin_connection: KeycloakAdmin, kafka_client, policies: dict, resources: dict
):
    """
    Create permissions for created resources

    :admin_connection: admin connection
    :kafka_client: name of central kafka client e.g. kafka
    :policies: list of poilicies to include in resources
    :resources: list of resources to include in policies
    """

    permission_set = []
    resources_set = []
    client = get_keycloak_client_by_name(
        admin_connection=admin_connection, client_name=kafka_client, get_scopes=True
    )

    scopes_set = client.get("scopes")
    scopes_transformed = {}
    payload = []
    # Transform scopes dict to {scopeName: scopeId}
    for s in scopes_set:
        scopes_transformed[s["name"]] = s["id"]

    client_resources = get_client_resources_dict(admin_connection, client["id"])
    for i in resources:
        resources_set.append(
            {
                "id": admin_connection.get_client_authz_resource(client_id=client["id"], resource_id=i)["_id"],
                "name": admin_connection.get_client_authz_resource(client_id=client["id"], resource_id=i)["name"]
            }
        )

    client_permissions = get_client_permissions_dict(admin_connection, client["id"])

    for i in resources_set:
        if "Cluster" in i["name"]:
            payload.append(
                {
                    "name": f"MM2:{i["name"]}",
                    # "type": "Scope",
                    # "logic": "POSITIVE",
                    "decisionStrategy": "UNANIMOUS",
                    "resources": [i["id"]],
                    "scopes": [
                        scopes_transformed["Describe"],
                        scopes_transformed["DescribeConfigs"],
                    ],
                    "policies": policies
                }
            )
        elif "Group" in i["name"]:
            payload.append(
                {
                    "name": f"MM2:{i["name"]}",
                    # "type": "Scope",
                    # "logic": "POSITIVE",
                    "decisionStrategy": "UNANIMOUS",
                    "resources": [i["id"]],
                    "scopes": [
                        scopes_transformed["Describe"],
                        scopes_transformed["DescribeConfigs"],
                        scopes_transformed["Read"],
                        scopes_transformed["Write"],
                        scopes_transformed["Create"],
                    ],
                    "policies": policies
                }
            )
        else:
            payload.append(
                {
                    "name": f"MM2:{i["name"]}",
                    # "type": "Scope",
                    # "logic": "POSITIVE",
                    "decisionStrategy": "UNANIMOUS",
                    "resources": [i["id"]],
                    "scopes": [
                        scopes_transformed["Describe"],
                        scopes_transformed["DescribeConfigs"],
                        scopes_transformed["Read"],
                        scopes_transformed["Write"],
                        scopes_transformed["Create"],
                        scopes_transformed["AlterConfigs"],
                        scopes_transformed["Alter"],
                    ],
                    "policies": policies
                }
            )

    for i in payload:
        logger.info(f"Creating permission {i}")
        if i["name"] in client_permissions:
            logger.warning(f"Permission {i["name"]} already exists")
            permission_set.append(client_permissions.get(i["name"]))
        else:
            try:
                admin_connection.create_client_authz_scope_permission(
                    payload=i, client_id=client["id"]
                )
            except Exception:
                logger.error(f"Error occured when creating permission")
                logger.error(traceback.format_exc().splitlines()[-1])
    return permission_set


config = read_config()
admin_connect = connect_to_keycloak(config)
client = create_keycloak_client(
    payload=config["client_config"], admin_connection=admin_connect
)
resources = create_keycloak_resource(
    admin_connection=admin_connect, kafka_client=config["resources"]["kafka_client_name"], payload=config
)
policies = create_keycloak_client_policy(
    admin_connection=admin_connect, kafka_client=config["resources"]["kafka_client_name"], target_client=client
)

create_keycloak_permissions(
    admin_connection=admin_connect,
    kafka_client=config["resources"]["kafka_client_name"],
    policies=policies,
    resources=resources,
)
