# 8. Реагирование на инциденты

Первое действие при любом подозрении на компрометацию — запретить изменения:

```sh
sudo nmsctl executor freeze on --reason 'инцидент: <кратко>'
```

Мониторинг, syslog и чтение продолжают работать. Снимается freeze только с хоста — после разбора.

## 8.1. Executor в freeze: причины и действия

Executor уходит в freeze сам и поднимает алерт, если не может доказать целостность своего состояния.

| Причина | Признак | Действие |
|---|---|---|
| Ручной freeze с хоста или запрос из панели | Алерт freeze, строка в аудите панели (`executor.freeze`) | Разобраться, затем `freeze off` (запрос из панели — `--drop-panel-request`) |
| Перебор TOTP изменений (`executor_bruteforce`) | Неудачи от 3+ пользователей, всего > 20 за час | Найти источник в аудите executor'а; `nmsctl executor unlock --global`, при необходимости `unlock U`; затем `freeze off` |
| Подмена реестра: MAC строки, откат счётчика, несовпадение хеша состояния | Алерт `disaster` | См. ниже: «Подмена реестра» |
| Разрыв цепочки аудита executor'а или изменение таблиц аудита (`executor_tamper`) | Алерт `disaster`, `nmsctl executor audit verify` сообщает разрыв | `registry reset --i-understand` (строки аудита не исправить) |
| Нет файла состояния в уже использованном томе executor'а | Freeze при старте | Восстановить согласованно БД и том через `nmsctl restore`; иначе `registry reset` |
| БД восстановлена без согласованного тома executor'а | Freeze при старте после восстановления | Восстанавливать только `nmsctl restore`; иначе `registry reset` |
| Ложный freeze после краха PostgreSQL в окне двухфазной записи | Алерт `disaster` после аварийного рестарта БД | Если `registry verify` проходит — `freeze off`, иначе `registry reset` |
| Незавершённая ротация ключа запечатывания | Executor остановлен или в freeze | Повторить `nmsctl executor key rotate` |
| Секрет TOTP изменений не открывается своим ключом (`executor_tamper`) | Алерт `disaster` | Как подмена реестра |

**Подмена реестра.** Подменить строки `exec` может только владелец или суперпользователь БД, то есть
root на хосте. Порядок:

1. Разобраться, кто имел доступ к хосту и БД (аудит хоста, `docker` логи).
2. `sudo nmsctl executor registry verify` и `sudo nmsctl executor audit verify`.
3. Если проверки проходят (ложное срабатывание) — `sudo nmsctl executor freeze off --reason '...'`.
4. Если нет — `sudo nmsctl executor registry reset --i-understand`. Сброс отзывает все гранты, удаляет
   все TOTP изменений и подтверждённые модели, выключает запись, `allow_ssh_rsa_sha1` и
   `backup_via_executor` на всех устройствах и снимает пины ключей хостов. Отчёт перечисляет сохранённые
   устройства с адресами как неподтверждённые — проверьте каждый адрес, затем заново: `enroll`, `grant`,
   `model-verify`, `device accept-hostkey`, `device writes on` ([04-executor.md](04-executor.md)).

## 8.2. Аудит панели и якоря

Цепочка аудита панели — хеш-цепочка в БД; таймер `nms-audit-anchor` ежечасно пишет её голову в
`/var/lib/nms/anchors/anchors.log` на хосте.

```sh
systemctl status nms-audit-anchor.timer
sudo nmsctl audit verify
sudo nmsctl audit anchor        # внеочередной якорь
```

`audit verify` завершается ошибкой при разрыве цепочки, несовпадении с якорем, отсутствии якорей при
событиях старше часа и если самый новый якорь старше 2 часов при более новых событиях (таймер
остановлен).

Регулярно копируйте `anchors.log` вне сервера: суперпользователь БД может переписать хвост журнала,
а root — и сам файл якорей. Для проверки по внешней копии положите её в `/var/lib/nms/anchors/` (только
этот каталог виден контейнеру `nmsctl`) и укажите путь:

```sh
sudo nmsctl audit verify --anchors /var/lib/nms/anchors/anchors-offsite.log
```

Аудит executor'а проверяется отдельно: `sudo nmsctl executor audit verify`; просмотр — `/x/audit`
(грант `audit-read` и TOTP изменений).

## 8.3. Подозрение на компрометацию api (панели)

Api не видит секретов устройств и не может снять freeze или выдать права на запись, но может подменять
данные панели и подписывать ticket'ы на любого пользователя.

1. `sudo nmsctl executor freeze on --reason '...'`.
2. Проверить аудит панели и executor'а: `nmsctl audit verify`, `nmsctl executor audit verify`, выдачи
   ticket'ов (`executor.ticket`), попытки на `/x`.
3. `sudo nmsctl keys rotate ticket` — украденный ключ подписи ticket'ов перестаёт работать.
4. Сбросить пароли и TOTP администраторов и затронутых пользователей:
   `sudo nmsctl user reset U --password --totp` (все сессии пользователя завершаются).
5. Найти в аудите панели изменения адресов устройств и CIDR сканов: подменённый адрес отправляет
   SNMP-учётку на чужой хост. Для SNMPv2c на таких устройствах смените community; для SSH защита —
   закреплённый ключ хоста.
6. Переустановить образы из проверенного бандла (`nmsctl update`) или восстановиться на чистый сервер.
7. `nmsctl executor registry verify`, затем `freeze off`.

## 8.4. Потеря TOTP

| Ситуация | Действие |
|---|---|
| Пользователь панели потерял TOTP входа | Резервный код; иначе `sudo nmsctl user reset U --totp` — при следующем входе пользователь привяжет TOTP заново |
| Забыт пароль | `sudo nmsctl user reset U --password [--password-file F]` |
| Учётная запись заблокирована неудачными входами | `sudo nmsctl user unlock U` |
| Недоступны все администраторы | `sudo nmsctl admin create --user U` — новый администратор с TOTP |
| Потерян TOTP изменений | `sudo nmsctl executor enroll U --replace` |
| Блокировка TOTP изменений | `sudo nmsctl executor unlock U` |

Сброс пароля и TOTP пользователей панели через веб невозможен — только `nmsctl`.

## 8.5. Утечка ключа

| Что утекло | Действие |
|---|---|
| Ключ read-домена | `nmsctl keys rotate read`; если утекла и копия БД — смените учётки чтения на устройствах и введите их в панели заново |
| Ключ write-домена | `nmsctl keys rotate write`; при утечке копии БД — смените пароли учёток записи на устройствах и введите их на `/x` |
| Ключ backup-домена | `nmsctl keys rotate backup`; при утечке копии БД считайте раскрытыми бэкапы конфигов и записи сессий (секреты в конфигах — сменить) |
| Ключ подписи ticket'ов | `nmsctl keys rotate ticket` |
| Ключ запечатывания executor'а | `nmsctl executor key rotate`; при утечке копии БД — `nmsctl executor enroll U --replace` для всех пользователей с TOTP изменений |
| TLS-ключ сервиса | `nmsctl certs rotate <имя>` |
| Архив ключей бэкапа вместе с парольной фразой | Раскрыт весь `/etc/nms`: выполнить все ротации выше и `nmsctl certs rotate`; ключ внутреннего CA и ключ бэкапа (`backup_age.key`) в этой версии командой не ротируются — учитывайте это при оценке ущерба |
| Учётки устройств | Сменить пароли на устройствах (через сессию изменений), обновить профили в панели или на `/x`; ACL «только с адреса сервера» ограничивает ущерб |

## 8.6. Источники для расследования

Аудит панели, аудит executor'а (`/x/audit`), записи сессий изменений, бэкапы конфигов с diff, журналы
контейнеров (`docker compose -f /etc/nms/compose.yaml logs <сервис>`).
