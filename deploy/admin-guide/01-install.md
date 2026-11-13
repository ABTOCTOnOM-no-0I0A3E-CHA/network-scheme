# 1. Установка

## 1.1. Требования

| Что | Требование |
|---|---|
| ОС | Linux (Ubuntu/Debian LTS), amd64; другие ОС установщик отвергает |
| Сервер | Для 5 000 устройств — 16 vCPU, 64 GB RAM, NVMe. Один узел, без HA |
| Docker | Docker Engine 24+ с плагином compose |
| `/etc/docker/daemon.json` | `"userland-proxy": false` (иначе eventd не видит реальный адрес источника syslog/трапов); `iptables` не выключен и `firewall-backend` — `iptables` (правила egress живут в цепочке `DOCKER-USER`). После правки — `systemctl restart docker` |
| Свободные порты хоста | 443/tcp, 8443/tcp, 514/udp, 514/tcp, 6514/tcp, 162/udp. Сетевой приём rsyslog/syslog-ng и `snmptrapd` на хосте нужно выключить |
| Время | NTP на хосте обязателен (TOTP, аудит, корреляция событий) |
| Образы | Загружены в локальный Docker заранее (см. 1.3): установщик ничего не скачивает |

Минимальный `daemon.json`:

```json
{ "userland-proxy": false }
```

Preflight проверяет ОС, версию Docker, `daemon.json`, занятость портов и отсутствие прежней установки
**до** того, как что-либо записать или спросить пароль.

## 1.2. Проверка `nmsctl` и бандла

`nmsctl` содержит ключ релиза, которым потом проверяется каждое обновление, поэтому его подлинность
проверяется до установки. Релиз состоит из файлов: `nms-<TAG>.tar` (бандл образов),
`nms-<TAG>.tar.minisig`, `nmsctl`, `SHA256SUMS`, `SHA256SUMS.minisig`. Открытый ключ релиза
`minisign.pub` получите от мейнтейнера по отдельному доверенному каналу.

```sh
minisign -V -p minisign.pub -m SHA256SUMS      # подпись списка контрольных сумм
sha256sum -c SHA256SUMS                         # nmsctl и бандл совпадают со списком
minisign -V -p minisign.pub -m nms-1.0.0.tar    # подпись самого бандла
sudo install -m 0755 nmsctl /usr/local/bin/nmsctl
```

Если любая проверка не прошла — не устанавливайте и сообщите мейнтейнеру.

## 1.3. Загрузка образов

Нужны образы `nms/api`, `nms/gateway`, `nms/executor` с одним тегом (из бандла) и образ БД
`timescale/timescaledb:2.30.2-pg17` с дайджестом, указанным в `compose.yaml` (в бандл он не входит).

```sh
mkdir /tmp/nms-bundle && tar -xf nms-1.0.0.tar -C /tmp/nms-bundle
for i in api gateway executor; do docker load -i /tmp/nms-bundle/images/$i.tar; done
rm -rf /tmp/nms-bundle
```

Образ БД загрузите из внутреннего registry-зеркала или перенесите `docker save` / `docker load` с
машины, где он есть. После установки `docker compose -f /etc/nms/compose.yaml config --images`
показывает, какие ссылки должны находиться локально (`docker image inspect <ссылка>`).

## 1.4. `nmsctl install`

```sh
sudo nmsctl install \
  --public-host nms.example.org \
  --image-tag 1.0.0 \
  --mgmt-subnet 192.0.2.0/24 \
  --infra-ntp ntp.example.org --infra-dns 192.0.2.53 --infra-mirror mirror.example.org
```

| Флаг | Назначение |
|---|---|
| `--public-host HOST` | DNS-имя или IPv4 панели (обязательно) |
| `--image-tag TAG` | Тег образов `nms/*` (обязательно) |
| `--mgmt-subnet CIDR` | Подсеть управления, куда poller и executor могут обращаться. Повторяется, минимум одна; только IPv4-адрес сети, без зарезервированных диапазонов |
| `--devices-subnet`, `--core-subnet`, `--xnet-subnet`, `--edge-subnet` | Внутренние подсети Docker. По умолчанию `172.30.1.0/24`, `172.30.0.0/24`, `172.30.2.0/24`, `172.30.3.0/24` — меняйте, если они пересекаются с вашими сетями |
| `--admin-user U` | Имя первого администратора (по умолчанию `admin`) |
| `--admin-password-file F` | Пароль из файла вместо запроса в терминале |
| `--web-cert F --web-key F` | Корпоративный веб-сертификат (PEM). Без них — сертификат от внутреннего CA |
| `--infra-ntp`, `--infra-dns`, `--infra-mirror` | Внутренние NTP, DNS, зеркало пакетов ОС через запятую. Записываются в конфигурацию как перечень разрешённой инфраструктуры для файрвола хоста (см. [02-firewall.md](02-firewall.md)) |
| `--non-interactive` | Не задавать вопросов; требует `--admin-password-file` |
| `--totp-secret-out F` | Только для CI: записать TOTP-секрет в файл |

Что делает установщик:

- генерирует внутренний CA и сертификаты сервисов, ключи доменов read/write/backup, ключ запечатывания
  executor'а, ключ подписи session ticket'ов, пароли ролей БД — всё в `/etc/nms/secrets`;
  повторная установка отвергается (`already installed`), секреты никогда не перегенерируются;
- записывает `compose.yaml`, конфиги сервисов и политику executor'а (`enabled: false`);
- ставит правила egress сети `devices` и drop-in `docker.service.d/nms-egress.conf` (Docker стартует
  только с этими правилами), таймер `nms-audit-anchor` (ежечасные якоря аудита), копирует себя в
  `/usr/local/bin/nmsctl`;
- поднимает стек и создаёт первого администратора.

Пароль: не короче 12 символов, проверяется по списку утёкших паролей.

## 1.5. Первый администратор и TOTP

В конце установки выводятся **один раз**:

- QR-код и секрет TOTP администратора — отсканируйте в приложении-аутентификаторе;
- резервные коды (каждый работает один раз) — сохраните в сейф;
- отпечатки ключей доменов read/write/backup, SHA-256 веб-сертификата и внутреннего CA — запишите:
  панель показывает те же отпечатки, сверьте их при первом входе.

Вход: `https://nms.example.org/`. Origin executor'а (подтверждение изменений, ввод учёток записи) —
`https://nms.example.org:8443/x`.

Ещё один администратор с хоста (например, запасной):

```sh
sudo nmsctl admin create --user admin2 [--password-file F]
```

Остальных пользователей создавайте в панели.

## 1.6. Веб-сертификат

- **Корпоративный:** укажите `--web-cert`/`--web-key` при установке. Сертификат должен содержать
  `--public-host`.
- **Внутренний CA (по умолчанию):** раздайте `/etc/nms/secrets/ca.crt` в доверенные корневые
  сертификаты браузеров или сверяйте отпечаток веб-сертификата из вывода установки. Перевыпуск —
  `nmsctl certs rotate web` ([07-rotation.md](07-rotation.md)).

## 1.7. Установки без executor'а (`nmsctl executor init`)

Установка, сделанная до появления executor'а, получает его одной командой (сначала загрузите образы
новой версии, включая `nms/executor`):

```sh
sudo nmsctl executor init --image-tag 1.0.0 [--xnet-subnet CIDR] [--edge-subnet CIDR]
```

Команда добавляет роль БД, недостающие секреты, сертификаты и ключ ticket'ов, перерисовывает файлы
текущими шаблонами (изменённые вами сохраняются как `<файл>.pre-executor`) и перезапускает сервисы.
Отказ: на свежей установке, после уже выполненного init, если порт 8443 занят. Прерванный запуск
доводится повторным. Политика остаётся `enabled: false` — дальше см. [04-executor.md](04-executor.md).
