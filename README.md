# Gitlab sync with ldap

- Work tested only with FreeIPA.
Functionality with OpenLDAP and other providers is not guaranteed and may require code modifications.

## Data Synchronization

- Users
  - Are not created automatically.
  - The username is synchronized (From the `displayName` attribute).
  - Admin status is synchronized (Based on group membership).
  - Accounts are blocked (*banned*) if they are removed from the `LDAP_GITLAB_USERS_GROUP` or if their password has been expired for more than 2 days. They are unblocked if the membership condition is fulfilled and the password is not expired.
  - SSH keys are synchronized (From the `ipaSshPubKey` attribute; synchronized keys have the prefix 'FreeIPA managed key').
  - Accounts are deleted if they are no longer present in LDAP.
- Groups
  - Are not created automatically.
  - Membership in Gitlab groups is synchronized based on LDAP groups. Access level is determined by the group name. If `ACCESS_LEVEL` is not specified, `GITLAB_GROUP_DEFAULT_ACCESS_LEVEL` env value is used as access level by default. Default value for `GITLAB_GROUP_DEFAULT_ACCESS_LEVEL` is `developer`
  - Nested groups follow the same group naming rules in LDAP, but all `/` in the group path are replaced with `--`.
  
  ```text
  {LDAP_GITLAB_GROUP_PREFIX}-{GROUPNAME}-{ACCESS_LEVEL}
  ```

  ***gitlab-group-test-owner*** - grants owner permissions in the test group.

  ***gitlab-group-test--nested-owner*** - grants owner permissions in the test/nested group.

  - `LDAP_GROUPS_GITLAB_USER_DEFAULT_PROJECT_COUNT` is default value for project limit. Default is 20.
  When users belongs to many of groups for limits used biggest value.
  
  ```text
  {LDAP_GITLAB_PROJECT_LIMIT_PREFIX}-{LIMIT}
  ```

  ***gitlab-prlimit-100000*** - Set project limit for members to 100000.

## Config

Configuration via environment variables.

- SYNC_DRY_RUN: Run in dry-run mode. Changes are not applied.
- GITLAB_API_URL: URL for accessing Gitlab (e.g. <https://gitlab.example.com>).
- GITLAB_TOKEN: Token for working with the Gitlab API. (e.g. glpat-xxxxx)
- GITLAB_LDAP_PROVIDER: Name of the LDAP provider as configured in Gitlab's LDAP settings.
(e.g. `ldapmain`. You can find it in the GitLab configuration or in the Admin Area by viewing the Identities tab of an existing user from your provider).
- LDAP_URL: URL for FreeIPA (e.g. ldap://ipa.example.com).
- LDAP_USERS_BASE_DN: Base DN for users.
- LDAP_GROUP_BASE_DN: Base DN for groups.
- LDAP_BIND_DN: Bind DN for LDAP.
- LDAP_PASSWORD: LDAP password.
- LDAP_GITLAB_USERS_GROUP: Group allowed to access Gitlab. Accounts are synchronized based on this group. Accounts not in this group are set to the banned state. Default value: `gitlab-users`.
- LDAP_GITLAB_ADMIN_GROUP: Group whose members have administrator rights in Gitlab. Default value: `gitlab-admins`.
- LDAP_GITLAB_GROUP_PREFIX: Prefix for LDAP groups used to synchronize Gitlab group members. Groups must already exist in Gitlab. Default value: `gitlab-group-`.
- GITLAB_GROUP_DEFAULT_ACCESS_LEVEL: Default access level for users in a group (if the group is specified without a role suffix). Allowed values: `owner`, `maintainer`, `developer`, `reporter`, `guest`. Default value: `developer`
- LDAP_GITLAB_PROJECT_LIMIT_PREFIX: Prefix for LDAP groups used to synchronize Gitlab users project limit. Default value: `gitlab-prlimit-`.
- GITLAB_USER_DEFAULT_PROJECT_LIMIT: Default project limit for users.
  Uses this value when user excluded from any `{LDAP_GITLAB_PROJECT_LIMIT_PREFIX}-{LIMIT}` groups.
  Default value 20.
- LDAP_GROUP_GITLAB_USER_CAN_CREATE_TL_GROUPS: Group to allow users create top-level groups.
  When value empty, sync do not perfomed. Default value ''.
