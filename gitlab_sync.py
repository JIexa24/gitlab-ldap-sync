#!/usr/bin/env python3
"""
Syncing users in gitlab with ldap provider.
Only one porovider are supported.
Sync users:
- attributes (fields)
- Ban if user exclude from access group or have expired password 2 days ago
- Unban if user return access or update password
Sync user fields:
- admin (LDAP: by group)
- name (LDAP: displayName attribute)
- SSH keys (LDAP: ipaSshPubKey attribute)
Sync groups:
- Doesn.t create non-existing groups
- Syncing users by members on ldap
- Doesn.t remove users which not managed by ldap
Version 2 at 03.2023
"""
# -*- coding: utf-8 -*-
# pylint: disable=line-too-long,import-error,no-member

import os
import logging
import datetime
import gitlab
import ldap
import ldap.asyncsearch

logging.basicConfig(level=logging.INFO)


class GitlabSync:
    """
    Sync gitlab users/groups with freeipa ldap
    """

    def __init__(self):
        sync_dry_run_env = os.getenv('SYNC_DRY_RUN')
        self.sync_dry_run = sync_dry_run_env if sync_dry_run_env else ''

        gitlab_api_url_env = os.getenv('GITLAB_API_URL')
        self.gitlab_api_url = gitlab_api_url_env if gitlab_api_url_env else ''
        gitlab_token_env = os.getenv('GITLAB_TOKEN')
        self.gitlab_token = gitlab_token_env if gitlab_token_env else ''
        gitlab_ldap_provider_env = os.getenv('GITLAB_LDAP_PROVIDER')
        self.gitlab_ldap_provider = gitlab_ldap_provider_env if gitlab_ldap_provider_env else 'ldapmain'
        ldap_url_env = os.getenv('LDAP_URL')
        self.ldap_url = ldap_url_env if ldap_url_env else ''
        ldap_users_base_dn_env = os.getenv('LDAP_USERS_BASE_DN')
        self.ldap_users_base_dn = ldap_users_base_dn_env if ldap_users_base_dn_env else ''
        ldap_group_base_dn_env = os.getenv('LDAP_GROUP_BASE_DN')
        self.ldap_group_base_dn = ldap_group_base_dn_env if ldap_group_base_dn_env else ''
        ldap_bind_dn_env = os.getenv('LDAP_BIND_DN')
        self.ldap_bind_dn = ldap_bind_dn_env if ldap_bind_dn_env else ''
        ldap_password_env = os.getenv('LDAP_PASSWORD')
        self.ldap_password = ldap_password_env if ldap_password_env else ''
        ldap_gitlab_users_group_env = os.getenv('LDAP_GITLAB_USERS_GROUP')
        self.ldap_gitlab_users_group = ldap_gitlab_users_group_env if ldap_gitlab_users_group_env else 'gitlab-users'
        ldap_gitlab_admin_group_env = os.getenv('LDAP_GITLAB_ADMIN_GROUP')
        self.ldap_gitlab_admin_group = ldap_gitlab_admin_group_env if ldap_gitlab_admin_group_env else 'gitlab-admins'
        ldap_gitlab_group_prefix_env = os.getenv('LDAP_GITLAB_GROUP_PREFIX')
        self.ldap_gitlab_group_prefix = ldap_gitlab_group_prefix_env if ldap_gitlab_group_prefix_env else 'gitlab-group-'
        ldap_group_compat_base_dn_env = os.getenv('LDAP_GROUP_COMPAT_BASE_DN')
        self.ldap_group_compat_base_dn = ldap_group_compat_base_dn_env if ldap_group_compat_base_dn_env else ''
        # pylint: disable=invalid-name
        self.gl = None
        self.ldap_obj = None
        self.ldap_gitlab_users = {}
        self.expired_ldap_gitlab_users = []
        date_expiration = datetime.datetime.now() - datetime.timedelta(days=2)
        password_expiration_border_date = date_expiration.strftime(
            "%Y%m%d%H%M%SZ")
        self.user_filter = f"(&(memberof=cn={self.ldap_gitlab_users_group},{self.ldap_group_base_dn})(!(nsaccountlock=TRUE)))"
        self.user_filter_with_uid = "(uid=%s)"
        self.expired_user_filter = f"(&(memberof=cn={self.ldap_gitlab_users_group},{self.ldap_group_base_dn})(!(nsaccountlock=TRUE))(krbPasswordExpiration<={password_expiration_border_date}))"
        self.admin_user_filter = f"(&(memberof=cn={self.ldap_gitlab_admin_group},{self.ldap_group_base_dn})(!(nsaccountlock=TRUE)))"

        logging.info('Initialize gitlab-ldap-sync')

    def check_config(self):
        """
        Check if config values are set
        """
        errors = 0
        if not self.gitlab_api_url:
            logging.error("GITLAB_API_URL is empty")
            errors = errors + 1
        if not self.gitlab_token:
            logging.error("GITLAB_TOKEN is empty")
            errors = errors + 1
        if not self.ldap_url:
            logging.error("LDAP_URL is empty")
            errors = errors + 1
        if not self.ldap_users_base_dn:
            logging.error("LDAP_USERS_BASE_DN is empty")
            errors = errors + 1
        if not self.ldap_group_base_dn:
            logging.error("LDAP_GROUP_BASE_DN is empty")
            errors = errors + 1
        if not self.ldap_bind_dn:
            logging.error("LDAP_BIND_DN is empty")
            errors = errors + 1
        if not self.ldap_password:
            logging.error("LDAP_PASSWORD is empty")
            errors = errors + 1
        if not self.ldap_group_compat_base_dn:
            logging.error("LDAP_GROUP_COMPAT_BASE_DN is empty")
            errors = errors + 1
        return errors

    def sync(self):
        """
        Sync gitlab entities
        """
        try:
            is_not_connected = 0
            is_not_connected += self.check_config()
            is_not_connected += self.connect_to_gitlab()
            is_not_connected += self.bind_to_ldap()
            if is_not_connected > 0:
                logging.error("Cannot connect, exit sync class")
                return
            self.search_all_users_in_ldap()
            self.sync_gitlab_users()
            self.sync_gitlab_groups()
        except Exception as expt:  # pylint: disable=broad-exception-caught
            logging.error("Cannot sync, received exception %s", expt)
            return

    def connect_to_gitlab(self):
        """
        Connect to gitlab using token
        """
        logging.info('Connecting to GitLab')
        if self.gitlab_token:
            self.gl = gitlab.Gitlab(url=self.gitlab_api_url,
                                    private_token=self.gitlab_token,
                                    ssl_verify=True)
        if self.gl is None:
            logging.error('Cannot create gitlab object, aborting')
            return 1
        self.gl.auth()
        return 0

    def bind_to_ldap(self):
        """
        Bind to LDAP
        """
        logging.info('Connecting to LDAP')
        if not self.ldap_url:
            logging.error('You should configure LDAP URL')
            return 1

        try:
            self.ldap_obj = ldap.initialize(uri=self.ldap_url)
            self.ldap_obj.simple_bind_s(self.ldap_bind_dn,
                                        self.ldap_password)
        except:  # pylint: disable=bare-except
            logging.error('Error while connecting to ldap')
            return 1
        if self.ldap_obj is None:
            logging.error('Cannot create ldap object, aborting')
            return 1
        return 0

    def search_all_users_in_ldap(self):
        """
        Search users in LDAP using filter
        """
        # pylint: disable=invalid-name
        for dn, user in self.ldap_obj.search_s(base=self.ldap_users_base_dn,
                                               scope=ldap.SCOPE_SUBTREE,
                                               filterstr=self.user_filter,
                                               attrlist=['uid',
                                                         'displayName',
                                                         'ipaSshPubKey']):
            username = user['uid'][0].decode('utf-8')
            self.ldap_gitlab_users[username] = {
                'admin': False,
                'displayName': user['displayName'][0].decode('utf-8'),
                'dn': dn,
                'ipaSshPubKey': user['ipaSshPubKey'] if 'ipaSshPubKey' in user else []
            }
        for dn, user in self.ldap_obj.search_s(base=self.ldap_users_base_dn,
                                               scope=ldap.SCOPE_SUBTREE,
                                               filterstr=self.admin_user_filter,
                                               attrlist=['uid']):
            username = user['uid'][0].decode('utf-8')
            if username in self.ldap_gitlab_users:
                self.ldap_gitlab_users[username]['admin'] = True
            else:
                logging.warning(
                    'User %s in admin group but does not have accesss to gitlab',
                    user.username)
        self.expired_ldap_gitlab_users = []
        for dn, user in self.ldap_obj.search_s(base=self.ldap_users_base_dn,
                                               scope=ldap.SCOPE_SUBTREE,
                                               filterstr=self.expired_user_filter, attrlist=['uid']):
            username = user['uid'][0].decode('utf-8')
            self.expired_ldap_gitlab_users.append(username)

    def is_ldap_user_exist(self, username):
        """
        Search user in LDAP using filter by uisername
        """
        # pylint: disable=invalid-name
        for _, _ in self.ldap_obj.search_s(base=self.ldap_users_base_dn,
                                           scope=ldap.SCOPE_SUBTREE,
                                           filterstr=(
                                               self.user_filter_with_uid % username),
                                           attrlist=['uid']):
            return True
        return False

    def ban_user(self, user, reason=''):
        """
        Ban user in gitlab
        """
        if user.state == 'active':
            if not self.sync_dry_run:
                user.ban()
            logging.info(
                'User %s has banned. Reason: %s',
                user.username, reason)

    def delete_user(self, user, reason=''):
        """
        Delete user in gitlab
        """
        # if not self.sync_dry_run:
        #     user.delete()
        logging.info(
            'User %s has deleted. Reason: %s',
            user.username, reason)

    def unban_user(self, user):
        """
        Unban user in gitlab.
        """
        if user.state == 'banned':
            if not self.sync_dry_run:
                user.unban()
            logging.info(
                'User %s unbanned',
                user.username)

    def sync_gitlab_users(self):
        """
        Sync users in gitlab.
        """
        for user in self.gl.users.list(all=True):
            if user.bot:
                logging.warning('User %s is bot', user.username)
                continue
            current_ldap_provider_user_dn = ''
            for i in user.identities:
                if i['provider'] == self.gitlab_ldap_provider:
                    current_ldap_provider_user_dn = i['extern_uid']
                    break
            if not current_ldap_provider_user_dn:
                logging.warning('User %s is not managed by ldap %s',
                                user.username, self.gitlab_ldap_provider)
                continue

            if user.username not in self.ldap_gitlab_users:
                if self.is_ldap_user_exist(user.username):
                    self.ban_user(
                        user, 'Disabled in ldap or excluded from access group')
                else:
                    self.delete_user(
                        user, 'Deleted in ldap')
                continue
            if user.username in self.expired_ldap_gitlab_users:
                self.ban_user(user, 'Has expired password')
                continue

            self.unban_user(user)

            need_to_update_user = False
            if self.ldap_gitlab_users[user.username]['admin'] != user.is_admin:
                logging.info('User %s, update is_admin %s->%s', user.username,
                             user.is_admin, self.ldap_gitlab_users[user.username]['admin'])
                user.admin = self.ldap_gitlab_users[user.username]['admin']
                need_to_update_user = True
            if self.ldap_gitlab_users[user.username]['displayName'] != user.name:
                logging.info('User %s, update name %s->%s', user.username,
                             user.name, self.ldap_gitlab_users[user.username]['displayName'])
                user.name = self.ldap_gitlab_users[user.username]['displayName']
                need_to_update_user = True

            if need_to_update_user:
                logging.info('Saving user %s', user.username)
                if not self.sync_dry_run:
                    user.save()
            self.sync_ssh_keys(user)

    def sync_ssh_keys(self, user):
        """
        Sync ssh keys (Only one direction FreeIPA -> Gitlab)
        """
        ipa_ssh_keys = self.ldap_gitlab_users[user.username]['ipaSshPubKey']
        gitlab_ssh_keys = user.keys.list()
        key_date = datetime.datetime.now().strftime("%Y-%m-%d")
        for ipa_ssh_key in ipa_ssh_keys:
            ipa_ssh_key_decoded = ipa_ssh_key.decode('utf-8')
            ipa_key_array = ipa_ssh_key_decoded.split()
            if len(ipa_key_array) < 2:
                logging.warning("One of ipa keys doesn.t have protocol or key")
                continue
            gitlab_key_id = self.is_ipa_key_in_gitlab_keys(
                ipa_ssh_key_decoded, gitlab_ssh_keys)
            if gitlab_key_id > 0:
                logging.info("Find existing key for user %s with id %s",
                             user.username, gitlab_key_id)
                continue
            try:
                title = f"FreeIPA managed key {key_date}"
                if len(ipa_key_array) > 2:
                    title = f"{title} {ipa_key_array[2]}"
                keyid = -1
                if not self.sync_dry_run:
                    key = user.keys.create({'title': title,
                                            'key': ipa_ssh_key_decoded})
                    keyid = key.id
                logging.info("Add key %d for user %s: %s", keyid,
                             user.username, title)
            except:  # pylint: disable=bare-except
                logging.error("Cannot add key for user %s: %s",
                              user.username, ipa_ssh_key_decoded)

        for gitlab_key in gitlab_ssh_keys:
            # If this key is not managed by sync and added manually - skip it
            if not gitlab_key.title.startswith('FreeIPA managed key'):
                continue
            is_ipa_key = self.is_gitlab_key_in_ipa_keys(
                gitlab_key.key, ipa_ssh_keys)
            if not is_ipa_key:
                logging.info("Remove key for user %s: %s",
                             user.username, gitlab_key.title)
                if not self.sync_dry_run:
                    gitlab_key.delete()

    def is_gitlab_key_in_ipa_keys(self, gitlab_key, ipa_keys):
        """
        Check if gitlab key exist in ipa keys array
        """
        g_key_array = gitlab_key.split()
        if len(g_key_array) < 2:
            logging.warning(
                "One of gitlab keys doesn.t have protocol or key")
            return False
        for ipa_ssh_key in ipa_keys:
            ipa_ssh_key_decoded = ipa_ssh_key.decode('utf-8')
            ipa_key_array = ipa_ssh_key_decoded.split()
            if len(ipa_ssh_key_decoded.split()) < 2:
                logging.warning("One of ipa keys doesn.t have protocol or key")
                continue
            # indicies: 0 - protocol, 1 - key
            if ipa_key_array[0] == g_key_array[0] and ipa_key_array[1] == g_key_array[1]:
                return True
        return False

    def is_ipa_key_in_gitlab_keys(self, ipa_ssh_key, gitlab_keys):
        """
        Check if ipa key exist in gitlab keys array
        """
        ipa_key_array = ipa_ssh_key.split()
        for g_key in gitlab_keys:
            g_key_array = g_key.key.split()
            if len(g_key_array) < 2:
                logging.warning(
                    "One of gitlab keys doesn.t have protocol or key")
                continue
            # indicies: 0 - protocol, 1 - key
            if ipa_key_array[0] == g_key_array[0] and ipa_key_array[1] == g_key_array[1]:
                return g_key.id
        return -1

    def get_gitlab_user_by_username(self, username):
        """
        Return user from gitlab by username
        """
        objects = self.gl.users.list(username=username)
        if len(objects) > 0:
            return objects[0]
        return None

    def fix_gitlab_group_member_access(self, group, member, access_level):
        """
        Fix access level to access_level
        """
        if member['object'].access_level != abs(access_level):
            logging.info("Update access level for %s in group %s: %d->%d",
                         member["username"], group.name, member['object'].access_level, abs(access_level))
            member['object'].access_level = abs(access_level)
            if not self.sync_dry_run:
                member['object'].save()

    def create_gitlab_group_member(self, group, user, level):
        """
        Create member in gitlab group
        """
        if not self.sync_dry_run:
            group.members.create(
                {'user_id': user.id, 'access_level': abs(level)})
        logging.info("Add %s(id=%d) to group %s with level %d",
                     user.username, user.id, group.name, abs(level))

    def remove_gitlab_group_member(self, groupname, user):
        """
        Remove member from gitlab group
        """
        logging.info("Remove %s from group %s",
                     user['username'], groupname)
        if not self.sync_dry_run:
            user['object'].delete()

    def get_ldap_group_access_level_by_name(self, groupname):
        """
        Return access level by group suffix
        """
        if groupname.endswith('-owner'):
            return gitlab.const.OWNER_ACCESS
        if groupname.endswith('-maintainer'):
            return gitlab.const.MAINTAINER_ACCESS
        if groupname.endswith('-developer'):
            return gitlab.const.DEVELOPER_ACCESS
        if groupname.endswith('-reporter'):
            return gitlab.const.REPORTER_ACCESS
        if groupname.endswith('-guest'):
            return gitlab.const.GUEST_ACCESS
        return -gitlab.const.DEVELOPER_ACCESS

    def get_ldap_gitlab_group_members(self, groupname):
        """
        Return members from ldap with access levels
        """
        gitlab_groups_prefix = f"cn={self.ldap_gitlab_group_prefix}{groupname}"
        gitlab_groups_filter = ''.join([
            "(|",
            f"({gitlab_groups_prefix})",
            f"({gitlab_groups_prefix}-owner)",
            f"({gitlab_groups_prefix}-maintainer)",
            f"({gitlab_groups_prefix}-developer)",
            f"({gitlab_groups_prefix}-reporter)",
            f"({gitlab_groups_prefix}-guest)",
            ")"
        ])

        # Find all gitlab groups in ldap
        ldap_members = {}
        for _, group in self.ldap_obj.search_s(base=self.ldap_group_base_dn,
                                               scope=ldap.SCOPE_SUBTREE,
                                               filterstr=gitlab_groups_filter,
                                               attrlist=['cn', 'description']):
            # pylint: disable=invalid-name
            g = group['cn'][0].decode('utf-8')

            level = self.get_ldap_group_access_level_by_name(g)

            # # Find all members of this ldap group.
            # # Need to use compat because it resolves subgroups
            gitlab_group_members_filter = f"(cn={g})"
            members_search = self.ldap_obj.search_s(base=self.ldap_group_compat_base_dn,
                                                    scope=ldap.SCOPE_SUBTREE,
                                                    filterstr=gitlab_group_members_filter,
                                                    attrlist=['memberUid'])
            if len(members_search) > 0:
                _, members_data = members_search[0]
                if 'memberUid' in members_data:
                    for x in members_data['memberUid']:
                        uid = x.decode('utf-8')
                        if uid not in ldap_members:
                            ldap_members[uid] = {
                                'access_level': level
                            }
                        else:
                            if ldap_members[uid]['access_level'] < level:
                                ldap_members[uid]['access_level'] = level
        return ldap_members

    def get_gitlab_group_members(self, group):
        """
        Return members of gitlab group
        """
        members = []
        for member in group.members.list(all=True):
            user = self.gl.users.get(member.id)
            members.append({
                'username': user.username,
                'object': member
            })
        return members

    def sync_gitlab_groups(self):
        """
        Sync groups in gitlab.
        """
        # TODO: Сделать вложенные группы
        logging.info('Sync groups')
        # gitlab_groups = {}
        for group in self.gl.groups.list(all=True):
            # gitlab_groups[group.path] = {
            #     "name": group.name,
            #     "members": self.get_gitlab_group_members(group),
            #     "object": group
            # }

            ldap_members = self.get_ldap_gitlab_group_members(group.name)
            gitlab_group_members = self.get_gitlab_group_members(group)
            # Group is not managed by ldap
            if len(ldap_members) == 0:
                continue

            # pylint: disable=invalid-name
            for m in gitlab_group_members:
                # Check if member not in ldap group
                if m['username'] in ldap_members:
                    continue
                user = self.get_gitlab_user_by_username(m['username'])
                # If user bot or not managed by current provider,
                # we cannot remove it
                if user.bot:
                    logging.warning('User %s is bot', user.username)
                    continue
                current_ldap_provider_user_dn = ''
                for i in user.identities:
                    if i['provider'] == self.gitlab_ldap_provider:
                        current_ldap_provider_user_dn = i['extern_uid']
                        break
                if not current_ldap_provider_user_dn:
                    logging.warning('Member %s is not managed by ldap %s',
                                    user.username, self.gitlab_ldap_provider)
                    continue
                self.remove_gitlab_group_member(group.name, m)

            root_member = next((
                item for item in gitlab_group_members if item["username"] == 'root'), None)
            root = self.get_gitlab_user_by_username('root')
            if not root_member:
                # Root user must be owner on all groups which synced
                self.create_gitlab_group_member(
                    group, root, gitlab.const.OWNER_ACCESS)

            # If root has access level lesser than owner - fix it
            if root_member:
                self.fix_gitlab_group_member_access(group,
                                                    root_member, gitlab.const.OWNER_ACCESS)

            for username, data in ldap_members.items():
                # If member exist in ldap group and not in gitlab - we need to add
                member = next((
                    item for item in gitlab_group_members if item["username"] == username), None)
                if member is None:
                    user = self.get_gitlab_user_by_username(username)
                    # If user never login - he.s account are not created in gitlab
                    # and we cannot add user to group, because we not create
                    # accounts while sync
                    if user is None:
                        logging.warning(
                            "User %s can.t be added to group %s because it not exist in gitlab. "
                            "User need to login before sync", username, group.name)
                        continue
                    # If user is member and exist in gitlab - add as developer member
                    self.create_gitlab_group_member(
                        group, user, data['access_level'])
                else:
                    # logging.info(member["object"])
                    # logging.info(member['object'].access_level)
                    self.fix_gitlab_group_member_access(
                        group, member, data['access_level'])
