import configparser
import traceback
import logging
from keycloak import KeycloakAdmin, KeycloakOpenIDConnection

# Base logger config
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def read_config():
    config= configparser.ConfigParser()
    config.read(r'config')

    keycloakConfig = dict(config.items("Keycloak"))

    return keycloakConfig

def connect_to_keycloak(config: dict):
    try:
        connection = KeycloakOpenIDConnection(
            server_url=config['url'],
            realm_name="kafka-authz",
            client_id=config['client'],
            client_secret_key=config['clientkey'],
            verify=False
        )

        admin = KeycloakAdmin(connection=connection)

        if len(admin.get_clients()) > 0:
            logger.info("Connection success")

    except Exception:
        logger.error("Error occured when creating connection to Keycloak")
        traceback.print_exc()

    return admin

def create_keycloak_client(payload: dict, admin_connection: KeycloakAdmin):
    try:
        new_client = admin_connection.create_client(payload=payload, skip_exists=False)
        
        logger.info(f"Client with ID {new_client} created!")
    
    except Exception:
        logger.error("Error occured when creating Client")
        traceback.print_exc()

client_config: dict = {
    "clientId": "test",
    "name": "test",
    "protocol": "openid-connect",
    "clientAuthenticatorType": "client-secret",
    "secret": "test-secret",
    "serviceAccountsEnabled":"true",
    "directAccessGrantsEnabled":"true",
    "publicClient": "false",
}

config = read_config()
admin_connect = connect_to_keycloak(config)
create_keycloak_client(payload=client_config, admin_connection=admin_connect)