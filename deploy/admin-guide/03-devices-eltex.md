# 3. Настройка устройств Eltex MES/ESR

Система **не настраивает** устройства сама: отправку syslog и трапов, учётки и ACL вы применяете
вручную. Ниже — сниппеты для трёх линеек ПО:

| Линейка | Модели |
|---|---|
| `mes6` | MES23xx/33xx/35xx/53xx/54xx/5500, ПО 6.x |
| `mes10` | MES14xx/24xx/3400/37xx, ПО 10.x |
| `esr` | ESR |

Синтаксис взят из документации производителя; стенда с реальным оборудованием у проекта нет. Строки с
пометкой **«проверить на вашей модели»** в просмотренной документации не подтверждены — сверьте их с
руководством к вашей модели и прошивке. `192.0.2.10` в примерах — адрес сервера NMS.

## 3.1. Общие рекомендации

- Отдельные учётки: одна только для чтения (poller), одна для записи (executor). Учётки панели и
  личные учётки администраторов не используйте.
- Ограничьте SNMP и SSH на устройствах адресом сервера NMS (ACL): это ограничивает ущерб, если
  учётка утечёт.
- SNMPv3 (authPriv, ключи от 16 символов: более слабые poller отвергает) вместо v2c. Community v2c
  уходит по сети открытым текстом.
- У каждого устройства — свой SSH-ключ хоста. Клоны с одинаковым ключом теряют SSH-чтение, пока любое
  из них в сессии изменений.
- На MES 6.x пароли по умолчанию стареют через 180 дней (`passwords aging`), на ESR срок задаёт
  `security passwords lifetime`. Учтите это для служебных учёток, иначе опрос и запись остановятся.
- SSH-учётку для чтения добавляйте в панели только после проверки адреса устройства: ключ хоста
  закрепляется при первом подключении.

## 3.2. SSH-сервер

Подтверждено документацией:

```
! MES 6.x: сервер выключен по умолчанию и работает только после генерации ключа
crypto key generate rsa
ip ssh server

! MES 10.x
crypto key generate ed25519
ssh enable

! ESR
ip ssh server
```

Отпечаток ключа хоста (для сверки при регистрации в executor'е): MES 6.x —
`show crypto key mypubkey rsa`, ESR — `show crypto key mypubkey`.

## 3.3. Учётка только для чтения (poller)

Poller выполняет только команды из встроенного allowlist'а (`show version`, `show system`,
`show interfaces status|counters`, `show vlan`, `show mac address-table`, `show arp`,
`show lldp neighbors`, `show ip route`) и для бэкапа — `show running-config`.

**MES 6.x** — бэкап конфига возможен учёткой без права настройки (подтверждено, пример производителя):

```
username nms-ro password <пароль> privilege 4
privilege exec 4 show running-config
```

**MES 10.x** — уровни 1–14 не дают настройки; понизить уровень отдельной команды в 10.x нельзя,
поэтому `show running-config`, по всей видимости, требует уровня 15:

```
username nms-ro password <пароль> privilege 1
```

**ESR** — уровни 1–9 дают только просмотр; `show running-config` требует уровня 10, который уже
разрешает настройку:

```
username nms-ro
 password <пароль>          ! проверить на вашей модели
 privilege 1
exit
```

Для MES 10.x и ESR бэкап конфигурации учёткой чтения невозможен без права записи: включите для таких
устройств бэкап через executor (`--backup-via-executor`, см. [04-executor.md](04-executor.md)).
Если устройство отвергнет `show running-config`, poller отметит это в панели.

Учётки чтения (SNMP и SSH) вводятся в панели в профилях доступа; они шифруются в браузере, сервер
панели их не видит.

## 3.4. SNMP

**Проверить на вашей модели** (синтаксис SNMP в просмотренной документации подтверждён лишь
частично):

```
! MES 6.x, SNMPv3 authPriv
snmp-server server
snmp-server group nms-ro v3 priv read <view>
snmp-server user nms-ro nms-ro v3 auth sha <auth-ключ> priv <priv-ключ>
! MES 6.x, SNMPv2c (только если v3 невозможен)
snmp-server community <community> ro 192.0.2.10

! ESR
snmp-server
snmp-server user nms-ro
 authentication algorithm sha1
 authentication key ascii-text <auth-ключ>
 privacy algorithm aes128
 privacy key ascii-text <priv-ключ>
 enable
exit
```

## 3.5. Syslog

Приём: UDP 514, TCP 514, TLS 6514; форматы RFC 3164/5424. **Проверить на вашей модели:**

```
! MES 6.x / 10.x
logging host 192.0.2.10

! ESR
syslog host nms
 remote-address 192.0.2.10
 transport udp
exit
```

Для TLS (6514) устройство должно доверять внутреннему CA сервера: `/etc/nms/secrets/ca.crt`. CA живёт
10 лет и не ротируется; сертификат syslog перевыпускается без перенастройки устройств.

## 3.6. Трапы

Приём: SNMP v1/v2c/v3 и INFORM v2c на UDP 162. INFORM v3 не поддерживается — для v3 настраивайте
трапы v3 или INFORM v2c. Трап запускает внеочередной опрос устройства. **Проверить на вашей модели:**

```
! MES 6.x / 10.x, v2c
snmp-server host 192.0.2.10 traps version 2c <community>
! MES, v3
snmp-server host 192.0.2.10 traps version 3 priv nms-ro

! ESR
snmp-server host 192.0.2.10
snmp-server enable traps
```

## 3.7. Учётка записи executor'а

Executor — единственный компонент, который пишет на устройства. Учётке нужен полный уровень:

```
! MES 6.x / 10.x (синтаксис подтверждён)
username nms-rw password <пароль> privilege 15

! ESR (уровень 15 — без ограничений)
username nms-rw
 password <пароль>          ! проверить на вашей модели
 privilege 15
exit
```

- Учётку записи **не вводите в панели**: её принимает только executor на
  `https://nms.example.org:8443/x` от пользователя с грантом `write-admin` и TOTP изменений.
- Ограничьте её ACL адресом сервера NMS и не используйте ни для чего другого.
- Запись на модель запрещена, пока модель и прошивка не подтверждены `nmsctl executor model-verify`
  (см. [04-executor.md](04-executor.md)).
- Смена ключа хоста на устройстве (`crypto key generate`, `update ssh-host-key` на ESR) ломает
  закреплённый ключ: executor откажет до `nmsctl executor device accept-hostkey`.
