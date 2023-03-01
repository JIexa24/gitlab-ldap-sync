#!/usr/bin/env python3
"""
Syncing users in gitlab with ldap provider.
Only one porovider are supported.
Sync user fields:
- admin
- name (displayName)
Version 1 at 2023
"""
# -*- coding: utf-8 -*-
# pylint: disable=line-too-long,import-error

import sys
import os
import logging
import gitlab
import ldap
import ldap.asyncsearch

logging.basicConfig(level=logging.INFO)

gitlab_api_url_env = os.getenv('GITLAB_API_URL')
gitlab_api_url = gitlab_api_url_env if gitlab_api_url_env else ''
gitlab_token_env = os.getenv('GITLAB_TOKEN')
gitlab_token = gitlab_token_env if gitlab_token_env else ''
gitlab_ldap_provider_env = os.getenv('GITLAB_LDAP_PROVIDER')
gitlab_ldap_provider = gitlab_ldap_provider_env if gitlab_ldap_provider_env else 'ldapmain'

ldap_url_env = os.getenv('LDAP_URL')
ldap_url = ldap_url_env if ldap_url_env else ''
ldap_users_base_dn_env = os.getenv('LDAP_USERS_BASE_DN')
ldap_users_base_dn = ldap_users_base_dn_env if ldap_users_base_dn_env else ''
ldap_group_base_dn_env = os.getenv('LDAP_GROUP_BASE_DN')
ldap_group_base_dn = ldap_group_base_dn_env if ldap_group_base_dn_env else ''
ldap_bind_dn_env = os.getenv('LDAP_BIND_DN')
ldap_bind_dn = ldap_bind_dn_env if ldap_bind_dn_env else ''
ldap_password_env = os.getenv('LDAP_PASSWORD')
ldap_password = ldap_password_env if ldap_password_env else ''
ldap_gitlab_users_group_env = os.getenv('LDAP_GITLAB_USERS_GROUP')
ldap_gitlab_users_group = ldap_gitlab_users_group_env if ldap_gitlab_users_group_env else 'gitlab-users'
ldap_gitlab_admin_group_env = os.getenv('LDAP_GITLAB_ADMIN_GROUP')
ldap_gitlab_admin_group = ldap_gitlab_admin_group_env if ldap_gitlab_admin_group_env else 'gitlab-admins'

if __name__ == "__main__":
    logging.info('Initializing gitlab-ldap-sync')
    logging.info('Connecting to GitLab')
    # pylint: disable=invalid-name
    gl = None
    if gitlab_token:
        gl = gitlab.Gitlab(url=gitlab_api_url,
                           private_token=gitlab_token, ssl_verify=True)
    if gl is None:
        logging.error('Cannot create gitlab object, aborting')
        sys.exit(1)
    gl.auth()

    logging.info('Connecting to LDAP')
    if not ldap_url:
        logging.error('You should configure LDAP URL')
        sys.exit(1)

    try:
        l = ldap.initialize(uri=ldap_url)
        l.simple_bind_s(ldap_bind_dn,
                        ldap_password)
    except:  # pylint: disable=bare-except
        logging.error('Error while connecting to ldap')
        sys.exit(1)

    logging.info('Getting all users from GitLab')
    gitlab_users = []

    USER_FILTER = f"(&(memberof=cn={ldap_gitlab_users_group},{ldap_group_base_dn})(!(nsaccountlock=TRUE)))"
    ADMIN_USER_FILTER = f"(&(memberof=cn={ldap_gitlab_admin_group},{ldap_group_base_dn})(!(nsaccountlock=TRUE)))"
    # ldap_gitlab_users = l.search_s(base=ldap_users_base_dn,
    #                                scope=ldap.SCOPE_SUBTREE,
    #                                filterstr=USER_FILTER)
    # ,
    #  attrlist=['uid', 'sAMAccountName', 'mail', 'displayName'])
    ldap_gitlab_users = {}
    for dn, user in l.search_s(base=ldap_users_base_dn,
                               scope=ldap.SCOPE_SUBTREE,
                               filterstr=USER_FILTER, attrlist=['uid', 'displayName']):
        username = user['uid'][0].decode('utf-8')
        ldap_gitlab_users[username] = {
            'admin': False,
            'displayName': user['displayName'][0].decode('utf-8'),
            'dn': dn
        }
    for dn, user in l.search_s(base=ldap_users_base_dn,
                               scope=ldap.SCOPE_SUBTREE,
                               filterstr=ADMIN_USER_FILTER, attrlist=['uid', 'displayName']):
        username = user['uid'][0].decode('utf-8')
        if username in ldap_gitlab_users:
            ldap_gitlab_users[username]['admin'] = True
        else:
            logging.warning(
                'User %s in admin group but does not have accesss to gitlab', user.username)

    for user in gl.users.list(all=True):
        # logging.info('Processing user %s', user.username)
        # logging.info(user)
        if user.bot:
            logging.warning('User %s is bot', user.username)
            continue
        current_ldap_provider_user_dn = ''
        for i in user.identities:
            if i['provider'] == gitlab_ldap_provider:
                current_ldap_provider_user_dn = i['extern_uid']
                break
        if not current_ldap_provider_user_dn:
            logging.warning('User %s is not managed by ldap %s',
                            user.username, gitlab_ldap_provider)
            continue

        need_to_update_user = False
        if user.username not in ldap_gitlab_users:
            logging.warning(
                'User %s may be disabled in ldap or excluded from access group',
                user.username)
            continue
        if ldap_gitlab_users[user.username]['admin'] != user.is_admin:
            logging.info('User %s, update is_admin %s->%s', user.username,
                         user.is_admin, ldap_gitlab_users[user.username]['admin'])
            user.admin = ldap_gitlab_users[user.username]['admin']
            need_to_update_user = True
        if ldap_gitlab_users[user.username]['displayName'] != user.name:
            logging.info('User %s, update name %s->%s', user.username,
                         user.name, ldap_gitlab_users[user.username]['displayName'])
            user.name = ldap_gitlab_users[user.username]['displayName']
            need_to_update_user = True
        if need_to_update_user:
            logging.info('Saving user %s', user.username)
            user.save()
