import requests
import json
import sys
import os
from requests.packages.urllib3.exceptions import InsecureRequestWarning

# suppress insecure request warning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


# session object to store credentials, token and ip address
class vmanage_session:
    def __init__(self, vmanage_ip, username, password):
        self.vmanage_ip = vmanage_ip
        self.session = {}
        self.login(self.vmanage_ip, username, password)

    def login(self, vmanage_ip, username, password):
        '''Login to vmanage'''
        base_url_str = 'https://%s/' % vmanage_ip
        login_action = '/j_security_check'
        token_action = 'dataservice/client/token'

        # payload for login
        login_data = {'j_username': username, 'j_password': password}

        # url for posting login data
        login_url = base_url_str + login_action

        # url for retrieving client token
        token_url = base_url_str + token_action

        sess = requests.session()

        # if the vmanage has a certificate signed by a trusted authority change verify to True
        login_response = sess.post(url=login_url,
                                   data=login_data,
                                   verify=False)

        if b'<html>' in login_response.content:
            print('Error: login failed')
            sys.exit(0)

        # get session token
        login_token = sess.get(url=token_url, verify=False)
        if login_token.status_code == 200:
            if b'<html>' in login_token.content:
                print('Error: login token not retrieved')
                exit(0)
            else:
                # storing token in the session header
                sess.headers['X-XSRF-TOKEN'] = login_token.content
        elif login_token.status_code == 404:
            # assume this is pre-19.2
            pass
        else:
            print('Error: login token not retrieved')
            exit(0)
        self.session[vmanage_ip] = sess

    def get_request(self, mount_point):
        '''GET request'''
        url = 'https://%s/dataservice/%s' % (self.vmanage_ip, mount_point)
        response = self.session[self.vmanage_ip].get(url, verify=False)
        data = response.content
        return data

    def post_request(self,
                     mount_point,
                     payload,
                     headers={
                         'Connection': 'keep-alive',
                         'Content-Type': 'application/json'
                     }):
        '''POST request'''
        url = 'https://%s/dataservice/%s' % (self.vmanage_ip, mount_point)
        payload = json.dumps(payload)
        response = self.session[self.vmanage_ip].post(url=url,
                                                      data=payload,
                                                      headers=headers,
                                                      verify=False)
        data = response.json()
        return data

    # vManage REST Calls
    def get_templates(self):
        mount_point = 'template/device'
        try:
            response = json.loads(self.get_request(mount_point))
            return response['data']
        except Exception as e:
            print('Error: vmanage_get_templates run into an exception')
            print(e)

    def get_process_status(self, process_id):
        mount_point = 'device/action/status/%s' % process_id
        try:
            response = json.loads(self.get_request(mount_point))
            data = {
                'data': response['data'],
                'validation': response['validation']
            }
            return data
        except Exception as e:
            print('Error: vmanage_get_process_status run into an exception')
            print(e)

    def get_ssh_devices(self):
        mount_point = 'newssh/devices'
        try:
            response = json.loads(self.get_request(mount_point))
            return response['data']
        except Exception as e:
            print('Error: vmanage_get_ssh_devices run into an exception')
            print(e)

    def attach_templates(self, template_id, device_data):
        mount_point = 'template/device/config/attachfeature'
        device_data['csv-status'] = 'complete'
        device_data['csv-templateId'] = str(template_id)
        device_data['selected'] = 'true'
        payload = {
            'deviceTemplateList': [{
                'templateId': str(template_id),
                'device': [device_data],
                'isEdited': 'false',
                'isMasterEdited': 'false'
            }]
        }
        try:
            response = self.post_request(mount_point, payload)
            return response['id']
        except Exception as e:
            print('Error: vmanage_attach_templates run into an exception')
            print(e)

    # Real Time Monitoring
    def get_control_connections(self, device_system_ip):
        mount_point = 'device/control/connections?deviceId=%s&&' % device_system_ip
        try:
            response = json.loads(self.get_request(mount_point))
            return response['data']
        except Exception as e:
            print(
                'Error: vmanage_get_control_connections run into an exception')
            print(e)

    def get_device_interfaces(self, device_system_ip):
        mount_point = 'device/interface?deviceId=%s&&' % device_system_ip
        try:
            response = json.loads(self.get_request(mount_point))
            return response['data']
        except Exception as e:
            print('Error: vmanage_get_device_interfaces run into an exception')
            print(e)
