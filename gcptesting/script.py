import json
import logging
import boto3
import json
import time
import requests

from pprint import pprint
from boto3.dynamodb.conditions import Attr
from boto3.dynamodb.conditions import Key
from google.auth import impersonated_credentials
from google.oauth2 import service_account
from googleapiclient.discovery import build

BASE_GCP_SCOPES = ["https://www.googleapis.com/auth/cloud-platform", "https://www.googleapis.com/auth/compute", "https://www.googleapis.com/auth/iam"]
DATE_FORMAT = "%Y-%m-%dT%H:%M:%S.%fZ"
AUTH_MAX_RETRIES = 6

def get_mgcp_target_crendentials(scopes=BASE_GCP_SCOPES):
    """Return GCP credentials for impersonated Service Account in Customer Project.
    .. note:: Used when you want to connect via Google's API to operate on a customer's account.
    .. seealso:: https://developers.google.com/identity/protocols/oauth2/scopes
    :param scopes: A list of required scopes for the API query
    :type scopes: list
    :return: GCP service account credentials for target customer project.
    """
    target_credentials = None
    logging.info(
        "Attempting to get an MGCP service account crendentials in target project."
    )
    for retries in range(AUTH_MAX_RETRIES):
        try:
            target_credentials = impersonated_credentials.Credentials(
                source_credentials=get_mgcp_source_credentials(),
                target_principal=get_mgcp_target_principal(),
                target_scopes=scopes,
            )
            break
        except requests.exceptions.RequestException as e:
            retry_wait = 2 ** (retries + 1)
            if AUTH_MAX_RETRIES <= (retries + 1):
                raise Exception(
                    "Maximum MGCP authentication retries of {} has been reached. Last error: {}".format(
                        str(AUTH_MAX_RETRIES), str(e)
                    )
                )
            time.sleep(retry_wait)
    if target_credentials:
        return target_credentials

    raise Exception("Could not obtain a valid MGCP credentials.")


def get_mgcp_source_credentials():
    """Return the service account credentials required to impersonation the Janus provisioned
    service account in a customer GCP project.
    .. seealso:: https://cloud.google.com/docs/authentication/production#passing_code
    .. seealso:: https://github.com/googleapis/google-api-python-client
    :param mgcp_key: MGCP Private Key
    :type mgcp_key: json object
    :return: An Oauth2 Object with GCP credentials.
    :rtype: object
    """
    mgcp_key = "/GastGCP/MGCP/Key"
    
    client = boto3.client("ssm")
    logging.info("Loading MGCP Service Account key from Parameter Store")
    service_account_info = json.loads(
        client.get_parameter(Name=mgcp_key, WithDecryption=True)
        .get("Parameter")
        .get("Value")
    )
    logging.info(service_account)

    source_scopes = BASE_GCP_SCOPES

    mgcp_source_credentials = (
        service_account.Credentials.from_service_account_info(
            service_account_info, scopes=source_scopes
        )
    )
    return mgcp_source_credentials


def get_mgcp_target_principal():
    """Return the Janus provisioned principal used for impersonation into a customer's GCP project.
    :return: A GCP Service Account Principal
    :param mgcp_principal: MGCP Principal for S/TAP Service account
    :type mgcp_principal: str
    :rtype: str
    """
    mgcp_principal = "/GastGCP/MGCP/Principal"

    client = boto3.client("ssm")
    logging.info("Loading MGCP Service Account Principal from Parameter Store")
    
    mgcp_target_principal = (
        client.get_parameter(Name=mgcp_principal, WithDecryption=True)
        .get("Parameter")
        .get("Value")
    )

    return mgcp_target_principal


def get_mgcp_builder(platform='compute', version='v1', creds=None):
    """Return the builder for the impersonated credentials
    :return: A GCP builder for the platform receiven in the parameters
    :param platform: MGCP Service
    :type platform: str
    :param version: Platform API version
    :type version: str
    :param creds: MGCP impersonated credentials
    :type platform: obj
    :rtype: builder
    """
    return build(platform, version, credentials=creds)


def get_Instances( mgcp_session, project_id):
    """Function for getting instances that are currently in the project.

    :param mgp_session: Credential session for GCP
    :type mg_session: Object
    :param project: Customer project
    :type project: String
    :return inst_list: List of available instances in the project
    rtype: list
    """
    instance_service = get_mgcp_builder(platform='compute', creds=mgcp_session)
    instances = instance_service.instances().list(project=project_id, zone="us-central1-a")
    inst_list = []
    while instances is not None:
        resp = instances.execute()
        
        if 'items' not in resp:
            print(resp)
            break
        for instances_scoped_list in resp['items']:
            # TODO: Change code below to process each (name, instances_scoped_list) item:
            #print(json.dumps(instances_scoped_list, indent=4))
            inst_list.append(instances_scoped_list)
        instances = instance_service.instances().list_next(previous_request=instances, previous_response=resp)
    #logging.info(json.dumps(inst_list, indent=4))
    return inst_list


def get_subnets(mgcp_session, project, region):
    subnet_builder = get_mgcp_builder(creds=mgcp_session)
    request = subnet_builder.subnetworks().list(project=project, region=region)
    while request is not None:
        response = request.execute()

        for subnetwork in response['items']:
            # TODO: Change code below to process each `subnetwork` resource:
            pprint(subnetwork)

        request = subnet_builder.subnetworks().list_next(previous_request=request, previous_response=response)


def get_routers(mgcp_session, project, region):
    router_builder = get_mgcp_builder(creds=mgcp_session)
    request = router_builder.routers().list(project=project, region=region)
    while request is not None:
        response = request.execute()

        for router in response['items']:
            # TODO: Change code below to process each `router` resource:
            pprint(router)

        request = router_builder.routers().list_next(previous_request=request, previous_response=response)

def list_subnets(mgcp_session, project):
    subnet_builder = get_mgcp_builder(creds=mgcp_session)
    request = subnet_builder.networks().list(project=project)
    subnets_list = []
    while request is not None:
        response = request.execute()

        for network in response['items']:
            # TODO: Change code below to process each `network` resource:
            pprint(network)
            for subnet in network["subnetworks"]:
                subnet_name = subnet.split('/')[-1]
                subnet_region = subnet.split('/')[8]
                subnet_dict = {
                    'name':subnet_name,
                    'region':subnet_region
                }
                subnets_list.append(subnet_dict)
                # testvar = f"{subnet_dict['name']} {subnet_dict['region']}"
                # print(testvar)

        request = subnet_builder.networks().list_next(previous_request=request, previous_response=response)
    for subnet in subnets_list:
        get_subnets_details(mgcp_session, project, subnet['region'], subnet['name'])

def get_subnets_details(mgcp_session, project, region, subnet):
    subnet_builder = get_mgcp_builder(creds=mgcp_session)
    request = subnet_builder.subnetworks().get(project=project, region=region, subnetwork=subnet)
    response = request.execute()
    print(response)


if __name__ == "__main__" :
        mgcp_session = get_mgcp_target_crendentials()
        resp = get_Instances(mgcp_session, "ops-will-west")
        print('''
        
Subnet Info
''')
        resp2 = get_subnets(mgcp_session, "ops-will-west", "us-central1")
        print('''
        
Router Info
''')
        resp3 = get_routers(mgcp_session, "ops-will-west", "us-central1")
        #print(json.dumps(resp,indent=2))
        print('''

Subnet_list Info
''')
        resp4 = list_subnets(mgcp_session, "ops-will-west")
        #print(json.dumps(resp,indent=2))