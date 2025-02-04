#!/usr/bin/env python

from ansible.module_utils.basic import *

DOCUMENTATION = '''
---
module: cisco_imc_ldap
short_description: Configure LDAP on a Cisco IMC server.
version_added: "0.9.0.0"
description:
  - TODO
options:
  TODO

requirements: ['imcsdk']
author: "Vikrant Balyan(vvb@cisco.com)"
'''

EXAMPLES = '''
TODO
'''


def _get_object_params(params):
    from ansible.module_utils.cisco_imc import ImcConnection
    args = {}
    for key in params:
        if (key == 'state' or
                ImcConnection.is_login_param(key) or
                params.get(key) is None):
            continue
        args[key] = params.get(key)
    return args


def setup(server, module):
    from imcsdk.apis.v2.admin.ldap import ldap_enable
    from imcsdk.apis.v2.admin.ldap import ldap_disable
    from imcsdk.apis.v2.admin.ldap import ldap_exists
    from imcsdk.apis.v2.admin.ldap import is_ldap_enabled

    results = {}
    err = False

    try:
        ansible = module.params

        args = _get_object_params(ansible)
        if ansible['state'] == 'present':
            exists, mo = ldap_exists(handle=server,
                                        admin_state='enabled',
                                        **args)
            if module.check_mode or exists:
                results["changed"] = not exists
                return results, False

            ldap_enable(handle=server, **args)
        elif ansible['state'] == 'absent':
            exists = is_ldap_enabled(handle=server)
            if module.check_mode or not exists:
                results["changed"] = (exists != False)
                return results, False

            ldap_disable(handle=server)

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
            basedn=dict(required=False),
            domain=dict(required=False),
            encryption=dict(required=False, default='enabled', type='str'),
            timeout=dict(required=False, default=60, type='int'),
            user_search_precedence=dict(required=False),
            bind_method=dict(required=False, default='login-credentials', type='str'),
            bind_dn=dict(required=False),
            ldap_password=dict(required=False, type='str', no_log=True),
            filter=dict(required=False, type='str'),
            attribute=dict(required=False, type='str'),
            group_attribute=dict(required=False, type='str'),
            group_nested_search=dict(required=False, type='str'),
            group_auth=dict(required=False, type='str'),
            ldap_servers=dict(required=False, type='list'),
            locate_directory_using_dns=dict(required=False, type='str'),  # yes or no
            dns_domain_source=dict(required=False, default='extracted-domain', type='str'),
            dns_search_domain=dict(required=False),
            dns_search_forest=dict(required=False),

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
