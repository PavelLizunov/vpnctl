# Spec: SSH user на setup-странице существующего сервера

## 1. Intent & Invariants

- What: `/admin/servers/{id}/setup` позволяет выбрать SSH user при установке deploy-ключа.
- Поле предварительно заполнено текущим `Server.ssh_user`; выбранное значение используется для password/reference-key SSH.
- Deploy-ключ записывается в `~/.ssh/authorized_keys` выбранного пользователя без sudo.
- После push демон проверяет свой deploy-key и точный non-root privilege primitive `sudo -n sh -c`.
- Новый `ssh_user` сохраняется только после успешного push и verification; ошибка оставляет прежнее значение.
- Audit фиксирует результат и выбранный `ssh_user`; пароль не сохраняется и не логируется.

## 2. Interface / Data Contract

```text
POST /admin/servers/{id}/push-deploy-key
ssh_user=debian
root_password=<password>
```

```rust
pub async fn exec_unprivileged(&self, remote_cmd: &str) -> Result<String>;
```

## 3. Verification Checklist

- [ ] Setup-форма показывает `ssh_user` из inventory.
- [ ] Невалидный пользователь отклоняется до подключения.
- [ ] Push выполняется как выбранный пользователь без sudo.
- [ ] Key-auth и passwordless sudo проверяются до изменения inventory.
- [ ] Успех сохраняет новый `Server.ssh_user` и audit; ошибка ничего не меняет.
- [ ] Review, GitHub CI, main CI и production deploy успешны.
- [ ] Production Bahnhof setup показывает поле SSH user и позволяет указать `debian`.
