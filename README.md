# Gitlab sync with ldap

## Синхронизация

- Учетные записи
  - Автоматически не создаются
  - Синхронизируется имя пользователя (Из свойства displayName)
  - Синхронизируется статус администратора (На основе членства в группе)
  - Блокируются (*ban), если исключены из группы LDAP_GITLAB_USERS_GROUP или имеют пароль, истекший более 2 дней назад. Разблокировка если условие членства выполняется и пароль не истек.
  - Синхронизируются ssh ключи (Из свойства ipaSshPubKey, синхронизированные ключи имеют префикс 'FreeIPA managed key')
- Группы
  - Автоматически не создаются
  - Синхронизируется по членству в группах LDAP. Уровень доступа определяется названием группы. Если ACCESS_LEVCEL не указан используется DEVELOPER-доступ
  
  ```text
  {LDAP_GITLAB_GROUP_PREFIX}-{GROUPNAME}-{ACCESS_LEVEL}
  ```

  ***gitlab-group-test-owner*** - права ***owner*** в группе ***test***

## Config

Конфигурация через переменные среды окружения

- SYNC_DRY_RUN: Запуск в режиме dry-run. Изменения не применяются
- GITLAB_API_URL: Url для обращения к Gitlab (Прим. - <https://gitlab.example.com>)
- GITLAB_TOKEN: Токен для работы с API Gitlab
- GITLAB_LDAP_PROVIDER: Имя провайдера, указанное в конфигурации ldap для Gitlab
- LDAP_URL: URL для FreeIPA (Прим. - ldap://ipa.example.com)
- LDAP_USERS_BASE_DN: Base DN для пользователей
- LDAP_GROUP_BASE_DN: Base DN для групп
- LDAP_BIND_DN: Bind DN в LDAP
- LDAP_PASSWORD: Пароль в LDAP
- LDAP_GITLAB_USERS_GROUP: Группа, которой разрешено заходить в гитлаб. На основании этой группы синхронизируются учетные записи. Учетные записи, не входящие в эту группу устанавливаются в состояние banned. Значение по умолчанию - ***gitlab-users***
- LDAP_GITLAB_ADMIN_GROUP: Группа, пользователи которой имеют права администратора в Gitlab. Значение по умолчанию - ***gitlab-admins***
- LDAP_GITLAB_GROUP_PREFIX: Префикс LDAP-групп для синхронизации членов групп Gitlab. Группы должны существовать в Gitlab. Значение по умолчанию - ***gitlab-group-***
- LDAP_GROUP_COMPAT_BASE_DN: Compat Base DN для групп. Отличается тем, что все вложенные группы разрешены и группа содержит полный список членов в т.ч. вложенных групп
