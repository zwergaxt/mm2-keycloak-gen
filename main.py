import configparser
import traceback
from keycloak import KeycloakAdmin, KeycloakOpenIDConnection


def readConfig():
    config= configparser.ConfigParser()
    config.read(r'config')

    keycloakConfig = dict(config.items("Keycloak"))

    return keycloakConfig

def connectToKeycloak(config):
    try:
        connection = KeycloakOpenIDConnection(
            server_url=config['url'],
            realm_name="kafka-authz",
            client_id=config['client'],
            client_secret_key=config['clientkey'],
            verify=False
        )

        admin = KeycloakAdmin(connection=connection)

        print(admin.get_clients())

    except Exception:
        traceback.print_exc()



config = readConfig()
connectToKeycloak(config)