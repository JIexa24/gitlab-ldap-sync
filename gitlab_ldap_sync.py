#!/usr/bin/env python3
"""
Syncing users in gitlab with ldap provider.
Only one porovider are supported.
Sync user fields:
- admin (LDAP: by group)
- name (LDAP: displayName attribute)
Sync groups:
- Doesn.t create non-existing groups
- Syncing users by members on ldap
- Doesn.t remove users which not managed by ldap
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
ldap_gitlab_group_prefix_env = os.getenv('LDAP_GITLAB_GROUP_PREFIX')
ldap_gitlab_group_prefix = ldap_gitlab_group_prefix_env if ldap_gitlab_group_prefix_env else 'gitlab-group-'
ldap_group_compat_base_dn_env = os.getenv('LDAP_GROUP_COMPAT_BASE_DN')
ldap_group_compat_base_dn = ldap_group_compat_base_dn_env if ldap_group_compat_base_dn_env else ''

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

    logging.info('Getting all users from GitLab and LDAP')
    gitlab_users = []

    USER_FILTER = f"(&(memberof=cn={ldap_gitlab_users_group},{ldap_group_base_dn})(!(nsaccountlock=TRUE)))"
    ADMIN_USER_FILTER = f"(&(memberof=cn={ldap_gitlab_admin_group},{ldap_group_base_dn})(!(nsaccountlock=TRUE)))"

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
            if user.state == 'active':
                logging.warning(
                    'User %s disabled in ldap or excluded from access group',
                    user.username)
                user.ban()
                logging.info(
                    'User %s has banned',
                    user.username)
            continue
        if user.state == 'banned':
            user.unban()
            logging.info(
                'User %s unbanned',
                user.username)
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

    # TODO: Сделать синхронизацию доступов. По умолчанию developer, при
    # наличии в группе {ldap_gitlab_group_prefix}-{group}-{level} давать level
    logging.info('Getting all groups from GitLab and LDAP')
    gitlab_groups = {}
    for group in gl.groups.list(all=True):
        members = []
        for member in group.members.list(all=True):
            user = gl.users.get(member.id)
            members.append({
                'username': user.username,
                'object': member
            })
        gitlab_groups[group.path] = {
            "name": group.name,
            "members": members,
            "object": group
        }

    GITLAB_GROUPS_FILTER = f"(cn={ldap_gitlab_group_prefix}*)"
    ldap_gitlab_groups = {}
    # Find all gitlab groups in ldap
    for dn, group in l.search_s(base=ldap_group_base_dn,
                                scope=ldap.SCOPE_SUBTREE,
                                filterstr=GITLAB_GROUPS_FILTER,
                                attrlist=['cn', 'description']):
        groupname = group['cn'][0].decode('utf-8')
        description = group['description'][0].decode('utf-8')
        # Find all members of this ldap group.
        # Need to use compat because it resolves subgroups
        GITLAB_GROUPS_MEMBERS_FILTER = f"(cn={groupname})"
        members_search = l.search_s(base=ldap_group_compat_base_dn,
                                    scope=ldap.SCOPE_SUBTREE,
                                    filterstr=GITLAB_GROUPS_MEMBERS_FILTER,
                                    attrlist=['memberUid'])
        groupname = groupname.removeprefix(ldap_gitlab_group_prefix)
        members_to_add = []
        members_to_remove = []
        ldap_members = []
        if len(members_search) > 0:
            _, members_data = members_search[0]
            if 'memberUid' in members_data:
                ldap_members = [x.decode('utf-8')
                                for x in members_data['memberUid']]
        if groupname not in gitlab_groups:
            logging.warning("Need to create group %s", groupname)
            continue

        # Iterate over all members in gitlab group
        gitlab_group = gitlab_groups[groupname]
        gitlab_group_members = gitlab_group["object"].members.list()
        for m in gitlab_group['members']:
            # Check if member not in ldap group
            if m['username'] not in ldap_members:
                user = gl.users.list(username=m['username'])[0]
                # If user bot or not managed by current provider,
                # we cannot remove it
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
                logging.info("Remove %s from group %s",
                             m['username'], groupname)
                m['object'].delete()

        root_member = next((
            item for item in gitlab_group['members'] if item["username"] == 'root'), None)
        root = gl.users.list(username='root')[0]
        if not root_member:
            # Root user must be owner on all groups which synced
            logging.info("Add root(id=%d) as owner to group %s",
                         root.id, groupname)
            gitlab_group["object"].members.create(
                {'user_id': root.id, 'access_level': gitlab.const.OWNER_ACCESS})

        # If root has access level lesser than owner - fix it
        if root_member and root_member['object'].access_level < gitlab.const.OWNER_ACCESS:
            root_member['object'].access_level = gitlab.const.OWNER_ACCESS
            root_member['object'].save()
            logging.info("Update root(id=%d) access level to owner")

        # Iterate over all members in ldap group
        for m in ldap_members:
            # If member exist in ldap group and not in gitlab - we need to add
            member_exist = next((
                item for item in gitlab_group['members'] if item["username"] == m), None)
            if member_exist is None:
                users = gl.users.list(username=m)
                # If user never login - he.s account are not created in gitlab
                # and we cannot add user to group, because we not create
                # accounts while sync
                if len(users) == 0:
                    logging.warning(
                        "User %s can.t be added to group %s because it not exist in gitlab. "
                        "User need to login before sync", m, groupname)
                    continue
                user = users[0]
                # If user is member and exist in gitlab - add as developer member
                gitlab_group["object"].members.create(
                    {'user_id': user.id, 'access_level': gitlab.const.DEVELOPER_ACCESS})
                logging.info("Add %s(id=%d) to group %s",
                             m, user.id, groupname)
