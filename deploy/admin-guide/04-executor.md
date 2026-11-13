# 4. Executor: изменение конфигураций

Executor — отдельный сервис, единственный, кто пишет на устройства. Он не доверяет панели: права,
адреса, ключи хостов, флаги записи и freeze берёт только из собственного реестра. Всё, что меняет его
права, делается только с хоста командами `nmsctl executor …` (`U` — имя пользователя панели или `#id`).
Каждая команда, включая отказанные, пишется в аудит executor'а.

Порядок первого включения: политика → включение → TOTP изменений → гранты → регистрация устройства →
учётка записи → подтверждение модели → разрешение записи на устройстве.

## 4.1. Политика и включение

Политика — `/etc/nms/policies/executor.yaml` (все ключи и значения по умолчанию — в
`deploy/policies/executor.yaml.example`): окна изменений, правило двух лиц, лимиты сессий и
changeset'ов, таймер `commit confirm-timeout` ESR, страховочный `reload in` MES и др.

```sh
sudo nmsctl executor policy show          # что читает executor
sudo nmsctl executor policy check         # проверить файл
sudo nmsctl executor policy edit          # править в $VISUAL/$EDITOR (vi); невалидная версия ничего не меняет
sudo nmsctl executor policy edit --file new.yaml
sudo nmsctl executor enable               # по умолчанию executor выключен
sudo nmsctl executor disable
```

Файл заменяется атомарно, executor перечитывает его сам. Невалидная политика выключает executor и
поднимает алерт.

## 4.2. TOTP изменений

Отдельный от входа TOTP, которым пользователь подтверждает сессии, опасные команды и changeset'ы.
Пользователь должен уже существовать в панели.

```sh
sudo nmsctl executor enroll ivanov              # покажет пользователя, спросит подтверждение, выведет QR один раз
sudo nmsctl executor enroll ivanov --replace    # перевыпуск: старый секрет перестаёт работать
```

`--yes` (без вопроса) и `--totp-secret-out F` — только для CI.

## 4.3. Гранты

```sh
sudo nmsctl executor grant ivanov write core-switches   # запись на устройства write-группы
sudo nmsctl executor grant ivanov write-admin           # регистрация устройств, учётки записи, ключи хостов
sudo nmsctl executor grant ivanov unmask                # просмотр конфигов без маскирования (только в своих write-группах)
sudo nmsctl executor grant ivanov audit-read            # просмотр аудита executor'а на /x/audit
sudo nmsctl executor revoke ivanov write core-switches
sudo nmsctl executor revoke ivanov --all
```

Write-группы executor'а — его собственные, они не связаны с группами устройств панели.

## 4.4. Регистрация устройства

`--device` — id устройства в панели, `--address` — IPv4 в подсети управления, `--group` — write-группа,
`--driver` — линейка `mes6`, `mes10` или `esr`.

```sh
sudo nmsctl executor device add --device 42 --address 192.0.2.21 --group core-switches --driver mes6
```

Executor сам читает ключ хоста и показывает его вместе с полями; сверьте отпечаток с консолью
устройства (см. [03-devices-eltex.md](03-devices-eltex.md), 3.2) и подтвердите. Доверия при первом
подключении (TOFU) нет: без подтверждения ключ не принимается. Если отпечаток известен заранее —
`--fingerprint SHA256:...`.

Дополнительные флаги: `--port P` (по умолчанию 22), `--allow-ssh-rsa-sha1` (ключ хоста ssh-rsa с SHA-1,
для старых MES 6.x), `--backup-via-executor` (бэкап конфигов делает executor учёткой записи — нужно для
MES 10.x и ESR). Флаг в форме `--flag=false` выключает его.

```sh
sudo nmsctl executor device accept-hostkey --device 42     # принять новый ключ хоста (замена устройства, перегенерация ключа)
sudo nmsctl executor device list
```

Регистрацию можно сделать и на `https://nms.example.org:8443/x` пользователем с `write-admin` и TOTP.

## 4.5. Учётка записи

Вводится только на `https://nms.example.org:8443/x` пользователем с `write-admin` и TOTP изменений.
Через панель (`:443`) ввести её нельзя. Учётка привязана к устройству и шифруется ключом write-домена.

## 4.6. Подтверждение модели (`model-verify`)

Поведение MES/ESR при записи известно по документации, а не по стенду. Поэтому запись на устройство
разрешена, только если его модель и прошивка (по `show version`, который читает сам executor) совпали
с подтверждённым профилем, иначе запись запрещена (чтение работает).

```sh
sudo nmsctl executor model-verify --driver mes6 --model 'MES2324.*' --firmware '6\.6\..*' \
  --note 'стенд, проверено: сессия, откат, changeset; Иванов, 2026-11-01'
```

`--model` и `--firmware` — регулярные выражения на всю строку (хранятся как `^(?:RE)$`).
`--strategy k=v` (повторяется) переопределяет стратегию поведения драйвера для этой модели. Подтверждайте
модель только после прогона записи, отката и changeset'а на тестовом экземпляре именно этой модели и
прошивки.

## 4.7. Разрешение записи на устройстве

```sh
sudo nmsctl executor device writes on --device 42
sudo nmsctl executor device writes off --device 42
```

## 4.8. Freeze

Freeze — мгновенный запрет любых изменений. Мониторинг и чтение продолжают работать.

```sh
sudo nmsctl executor freeze on --reason 'расследование'
sudo nmsctl executor freeze off --reason 'разбор завершён' [--drop-panel-request]
```

- Включить могут Admin в панели (запрос с step-up) и хост. Снять — **только хост**.
- `freeze off` проходит, только если успешны полная проверка цепочки аудита executor'а и проверка
  реестра. Ожидающий запрос freeze из панели заморозил бы снова — `--drop-panel-request` сбрасывает
  его в той же транзакции.
- Причины freeze и порядок действий — [08-incidents.md](08-incidents.md).

## 4.9. Разблокировки и проверки

```sh
sudo nmsctl executor unlock ivanov       # блокировка за неверные коды TOTP изменений
sudo nmsctl executor unlock --global     # очистить глобальное окно неудач (автоматический freeze по перебору)
sudo nmsctl executor registry verify     # проверка реестра (MAC строк, счётчик, хеш состояния)
sudo nmsctl executor audit verify        # полная проверка цепочки аудита executor'а
```

После 3 блокировок подряд пользователь разблокируется только `unlock`.
