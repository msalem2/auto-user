#!/usr/bin/env python3

from keystoneclient.auth.identity import v3
from keystoneclient import session
from keystoneclient.v3 import client as keystone_client
from neutrinoclient import client as neutrino_client
from neutrinoclient.exc import HTTPConflict
from keystoneclient.exceptions import Conflict
from novaclient import client as nova_client
from novaclient.v2 import quotas as nquotas
from cinderclient.v2 import quotas as ccquota
from cinderclient import client as cinder_client
from neutronclient.v2_0 import client as neutron_client
import pika
import argparse
import os
import sys
import logging
import requests
import json
from os.path import join, dirname
from dotenv import load_dotenv
from random import randint
from retry import retry

logger = logging.getLogger("npdt")
TEST_MODE = False

class Setup(object):
    def __init__(self, username, password, domain, host,domain_id,herodomain,herouser,herouserpass,default_project,firstname,lastname,email ):
        self.username = username
        self.password = password
        self.domain = domain
        self.host = host
        self.domain_id = domain_id
        self.herouser=herouser
        self.project=herodomain
        self.account=herodomain
        self.heropass=herouserpass
        self.created_users = set()
        self.default_password=password
        self.default_project=default_project
        self.firstname=firstname
        self.lastname = lastname
        self.email = email

    @retry(delay=2)
    def start(self):
        self.__authenticate()
        account = self.__create_account(self.account)
        account_domain = self.__get_domain_by_account_name(self.account)
        hero_project="project_"+self.account
        project = self.__get_project_by_name(hero_project,domain_id=account_domain.id)
        member=self.__create_user(account=account,project=project,domain=account_domain)
        self.__grant_roles(member,account=account, project=project,domain=account_domain,rolename="_member_")
        self.__set_project_quota(project=project)

        print("set cloud monitor account")
        #add user as Cloud Monitor to default domain
        defaultdomain=self.__get_domain_by_account_name(self.domain)
        defaultproject=self.__get_project_by_name(self.default_project,domain_id=defaultdomain.id)
        monitoruser = self.__create_user(account=account, project=defaultproject, domain=defaultdomain)
        self.__grant_roles(monitoruser,account=account,  project=defaultproject, domain=defaultdomain, rolename="monitor")
        self.__send_email(self.firstname,self.lastname,self.email)

    def __authenticate(self):
        if TEST_MODE:
            return
        logger.info("Start authentication with host %s", self.host)
        auth_url = "https://{}:6100/v3".format(self.host)
        admin_url = "https://{}:35357/v2.0".format(self.host)
        self.admin_url=admin_url
        auth = v3.Password(auth_url=auth_url, username=self.username, password=self.password, user_domain_name=self.domain, domain_id=self.domain_id)
        sess = session.Session(auth=auth, verify=False)
        logger.info("Create keystone client")
        self.keystone = keystone_client.Client(session=sess)
        logger.info("Create neutron client")
        self.neutron = neutron_client.Client(session=sess)
        neutrino_endpoint = "http://{}:35359".format(self.host)
        self.neutrino = neutrino_client.Client('1', endpoint=neutrino_endpoint, session=sess)
        logger.info("competed authentication with host %s",self.host)

    def __create_account(self, account):
        logger.info("Creating account '%s'" % (self.account ))
        if TEST_MODE:
            return '1'
        try:
            account = self.neutrino.accounts.create(name=self.account, description=self.account)
            print(account.id)
        except HTTPConflict as e:
            logger.warn("Account '%s' already exists. Getting account...", account['name'])
            account = self.neutrino.accounts.get(account['name'])
            logger.info("Got account '%s' (ID: %s)", account.name, account.id)
        logger.info("completed creating account %s",self.account)
        # Get primary domain

        return account

    def __get_domain_by_account_name(self, account_name):
        logger.info("get domain by acctount %s", account_name)
        domains = self.keystone.domains.list()
        for domain in domains:
            d = self.keystone.domains.get(domain)
            if d.name.lower()==account_name.lower():
               logger.info("Found domain id {%s} for account_name %s",d.id,account_name)
               return d
        raise Exception("domain not found '%s'" % (account_name,))

    def __create_project(self, project, account=None, domain=None):
        logger.info("Creating project '%s'" % (self.project, ))
        if TEST_MODE:
            return '1'
        try:
            project = self.keystone.projects.create(self.project, domain=domain, description=self.project)

        except Conflict as e:
            logger.warn("Project '%s' already exists. Getting project...", project['name'])
            project = self.__get_project_by_name(self.project, domain_id=self.domain)
            logger.info("Got project '%s' (ID: %s)", project.name, project.id)
        print("completed create project %s",self.project)
        return project

    def __get_project_by_name(self, project_name, domain_id=None):
        logger.info("get project Info by project name %s", project_name)
        projects = self.keystone.projects.list(domain=domain_id)
        for project in projects:
            if project.name.lower() == project_name.lower():
                logger.info("Found project id {%s} for account %s",project.id,self.account)
                return project
        raise Exception("Project not found '%s'" % (project_name,))

    def __create_user(self, account=None, project=None,domain=None):
        logger.info("Creating user '%s (%s)'" % (self.herouser,self.heropass))
        if TEST_MODE:
            return '1'
        domain_id = domain.id
        try:
            u = self.keystone.users.create(self.herouser, domain=domain_id, default_project=project.id, description=self.herouser, password=self.heropass)
            self.created_users.add(u.name)
        except Conflict as e:
            logger.warn("User '%s' already exists. Getting user...", self.username)
        return u

    def __set_project_quota(self,project=None):
        logger.info("Update Quota for Project ID %s",project.id)
        #update Neutron
        dd = {'quota': {'subnet': os.environ.get("SUBNET"),
                        'network': os.environ.get("NETWORK"),
                        'security_group_rule': os.environ.get("SECURITY_GROUP_RULES"),
                        'port': os.environ.get("PORT"),
                        'router': os.environ.get("ROUTER"),
                        'floatingip': os.environ.get("FLOATING_IPS"),
                        'security_group': os.environ.get("SECURITY_GROUPS")}}
        logger.info("Neutron quota %s",dd)
        self.neutron.update_quota(tenant_id=project.id, body=dd)

        # update Cinder
        logger.info("Update Project %s Cinder Quota",project.id)
        p_cinder = cinder_client.Client('2', self.username, self.password, self.default_project, self.admin_url, insecure=True)
        quota_data1 = dict(volumes=os.environ.get("VOLUMES"),
                           gigabytes=os.environ.get("GIGABYTES"),
                           snapshots=os.environ.get("SNAPSHOTS"))
        logger.info("Cinder quota %s",quota_data1)
        cinder_quota = ccquota.QuotaSetManager(p_cinder)
        cinder_quota.update(tenant_id=project.id, **quota_data1)

        logger.info("Update Project %s Nova Quota",project.id)
        p_nova = nova_client.Client('2', self.username, self.password, self.default_project, self.admin_url,insecure=True)
        quota_data = dict(metadata_items=os.environ.get("METADATA_ITEMS"),
                          injected_file_content_bytes=os.environ.get("INJECTED_FILE_CONTENT_BYTES"),
                          ram=os.environ.get("RAM"),
                          instances=os.environ.get("INSTANCES"),
                          injected_files=os.environ.get("INJECTED_FILES"),
                          cores=os.environ.get("CORES"),
                          )
        logger.info("Nova quota %s",quota_data)
        nova_quota = nquotas.QuotaSetManager(p_nova)
        nova_quota.update(tenant_id=project.id, **quota_data)

    def __grant_roles(self, user, account=None, project=None,domain=None,rolename=""):
        #print ("user %s", user.id)
        #print ("project %s",project.id)
        #print ("account %s",account.id)
        #print ("domain %s" ,domain.id)
        r = self.__get_role_by_name(rolename)
        print("Role ID %s name %s",r.id,r.name)
        if account:
            self.keystone.roles.grant(r.id, user=user.id, domain=domain.id)
        if project:
           self.keystone.roles.grant(r.id, user=user.id, project=project.id)
        print("complete grante user %s role",rolename)

    def __get_user(self, user_name, domain_id, project_id):
        users = self.keystone.users.list(domain=domain_id, default_project=project_id)
        for user in users:
            if user.name.lower() == user_name.lower():
                return user
        raise Exception("User not found '%s'" % (user_name,))

    def __get_role_by_name(self, role_name):
        roles = self.keystone.roles.list()
        for role in roles:
            if role.name.lower() == role_name.lower():
                return role
        raise Exception("Role not found '%s'" % (role_name,))

    def __send_email(self,firstname,lastname,email):
        logger.info("Send Email to %s %s at email %s",self.firstname,self.lastname,self.email)
        key = "api:"+os.environ['MAILGUN_KEY']
        request_url = os.environ['MAILGUN_BOX']
        sender = os.environ['MAILGUN_SENDER']
        body = "Hello "+firstname+" "+lastname+"</br></br>"
        body = body + "Welcome to Neutrino Hero game competition, here is your login information </br>"
        body = body + "domain:" + self.account+"</br>"
        body = body + "User Name:" + self.herouser+"</br>"
        body = body + "Password:" + self.heropass+"</br>"
        body = body + "Good Luck! </br></br> Neutrino Hero Team "

        data = {"from": sender,
                "to": email,
                "subject": "Welcome to Neutrino Hero Game",
                "html": body}

        request = requests.post(request_url, auth=('api', key), data=data,verify=False)

        logger.info("Finished sending Email to %s %s at email %s", self.firstname, self.lastname, self.email)


    def process_msg(message):

        try:
            data = json.loads(message.decode("utf-8"))
        except ValueError as e:
            print('Could not parse JSON data. %s' % (str(e),))
            return True
        try:
            hero_domain = data['first_name'] + data['last_name'] + str(randint(1111, 9999))
            #userpass = ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(8))

            #logger.info("hero user name %s",username)
            #logger.info("hero password %s",userpass)

            dotenv_path = join(dirname(__file__), '.env')
            load_dotenv(dotenv_path)
            host = os.environ.get("HOST")
            admin_name = os.environ.get("ADMIN_NAME")
            admin_pass = os.environ.get("PASSWORD")
            admin_domain = os.environ.get("ADMIN_DOMAIN_NAME")
            domain_id= os.environ.get("ADMIN_DOMAIN_ID")
            defaultproject = os.environ.get("ADMIN_PROJECT_NAME")
            c = Setup(admin_name, admin_pass, admin_domain, host, domain_id,hero_domain,data['hero_name'],data['password'],defaultproject,data['first_name'] , data['last_name'],data['email'] )
            c.start()
        except Exception as e:
            logger.error("Error running the setup script. Error:", e)


# Main Execution
def main():
    logging.basicConfig()
    logger.setLevel(logging.DEBUG)
    parser = argparse.ArgumentParser(
        description='Script to create the Hero Account, user and project quota ')
    parser.add_argument('--firstname', help='Hero User First Name',
                        required=False, default='admin')
    parser.add_argument('--lastname', help='Hero User Last Name.',
                        required=False, default='admin123')
    global TEST_MODE
    TEST_MODE = False

    try:

        dotenv_path = join(dirname(__file__), '.env')
        load_dotenv(dotenv_path)

        rmq_host = os.getenv('RABBITMQ_HOST', 'rabbit')
        rmq_port = int(os.environ['RABBITMQ_PORT'])
        rmq_user = os.environ['RABBITMQ_USER']
        rmq_password = os.environ['RABBITMQ_PASSWORD']
        queue_name = os.environ['QUEUE_NAME']

        connection = pika.BlockingConnection(pika.ConnectionParameters(
        host=rmq_host, port=rmq_port, credentials=pika.PlainCredentials(rmq_user, rmq_password)))
        channel = connection.channel()
        channel.queue_declare(queue=queue_name, durable=True)

        print(' [*] Waiting for Message. To exit press CTRL+C')

        def callback(ch, method, properties, body):
            print(" [x] received %r" % body)
            Setup.process_msg(body)
            print(" [x] Done")
            #ch.basic_ack(delivery_tag=method.delivery_tag)


        channel.basic_qos(prefetch_count=1)
        channel.basic_consume(callback, queue=queue_name,no_ack=True)
        channel.start_consuming()

    except Exception as e:
        print("Error running the setup script. Error:", e)
        sys.exit(1)
    print("Setup script completed successfully")
    sys.exit(0)

if __name__ == "__main__":
    main()
