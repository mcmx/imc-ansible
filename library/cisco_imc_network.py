#!/usr/bin/env python

from ansible.module_utils.basic import *

DOCUMENTATION = '''
---
module: cisco_imc_ntp
short_description: Setup Network on a Cisco IMC server.
version_added: "0.9.0.0"
description:
  - Setup Network on a Cisco IMC server.
options:
  state:
    description: Enable/Disable NTP
    default: "present"
    choices: ["present", "absent"]
    required: true
  ntp_servers:
    description: Dictionary of NTP servers to be configured {"id":"", "ip":""}
    required: false

requirements: ['imcsdk']
author: "Swapnil Wagh(swwagh@cisco.com)"
'''

EXAMPLES = '''
- name: enable ntp
  cisco_imc_ntp
    ntp_servers:
      - {"id": "1", "ip": "192.168.1.1"}
      - {"id": "2", "ip": "192.168.1.2"}
    ip: "192.168.1.1"
    username: "admin"
    password: "password"
    state: "present"
'''

def setup(server, module):
    from imcsdk.apis.v2.admin.network import mgmt_if_configure
    from imcsdk.apis.v2.admin.network import mgmt_if_exists

    results = {}
    err = False

    try:
        ansible = module.params
        if ansible['state'] == 'present':
            exists, mo = mgmt_if_exists(
                                    server,
                                    dns_preferred=ansible.get('dns_preferred', None),
                                    dns_alternate=ansible.get('dns_alternate', None))
            if module.check_mode or exists:
                results["changed"] = not exists
                return results, False

            mgmt_if_configure(
                        server,
                        dns_preferred=ansible.get('dns_preferred', None),
                        dns_alternate=ansible.get('dns_alternate', None))
        elif ansible['state'] == 'absent':
            # Dont know how to do this yet
            exists = True
            if module.check_mode or exists:
                results["changed"] = not exists
                return results, False

        results['changed'] = True

    except Exception as e:
        err = True
        results["msg"] = str(e)
        results["changed"] = False

    return results, err


def main():
    from ansible.module_utils.cisco_imc import ImcConnection
    module = AnsibleModule(
        argument_spec=dict(
            dns_preferred=dict(required=True, type='str'),
            dns_alternate=dict(required=True, type='str'),
            state=dict(required=True,
                       choices=['present', 'absent'], type='str'),

            # ImcHandle
            server=dict(required=False, type='dict'),

            # Imc server credentials
            ip=dict(required=False, type='str'),
            username=dict(required=False, default="admin", type='str'),
            password=dict(required=False, type='str', no_log=True),
            port=dict(required=False, default=None),
            secure=dict(required=False, default=None),
            proxy=dict(required=False, default=None)
        ),
        supports_check_mode=True
    )

    conn = ImcConnection(module)
    server = conn.login()
    results, err = setup(server, module)
    conn.logout()
    if err:
        module.fail_json(**results)
    module.exit_json(**results)


if __name__ == '__main__':
    main()
