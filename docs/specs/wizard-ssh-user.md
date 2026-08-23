# Spec: SSH-пользователь в мастере добавления сервера

## 1. Intent & Invariants

- What: добавить в `/admin/servers/new` поле SSH user, чтобы сервер можно было подключить как `debian`, а не только как `root`.
- Пустое поле означает `root`; текущее поведение и старые серверы не меняются.
- Выбранный пользователь применяется к password-auth, deploy-key, key-auth и сохраняется в `Server.ssh_user`.
- Для пользователя не `root` мастер проверяет `sudo -n`; последующие привилегированные SSH-команды выполняются через беспарольный sudo.
- Логин валидируется до SSH; пароль не выводится в HTML, SSE, Debug, audit или логах.

## 2. Interface / Data Contract

```rust
pub struct WizardSession {
    pub address: String,
    pub ssh_user: String,
    pub root_password: String,
    pub ssh_port: u16,
    pub created: Instant,
}

pub struct BootstrapPlan {
    pub server_id: String,
    pub address: String,
    pub ssh_user: String,
    pub ssh_port: u16,
    pub root_password: String,
    pub deploy_key_path: PathBuf,
    pub known_hosts_path: PathBuf,
}

pub fn validate_ssh_user(input: &str) -> Result<&str, &'static str>;
```

Web form: `name="ssh_user"`, default `root`; examples: `root`, `debian`, `ubuntu`.

## 3. Verification Checklist

- [ ] Пустой `ssh_user` и `root` сохраняют прежний root-flow.
- [ ] `debian` проходит session → plan → SSH transport → inventory.
- [ ] Deploy-ключ записывается в `~debian/.ssh/authorized_keys`.
- [ ] Для non-root заранее проверяется точный execution primitive `sudo -n sh -c true`.
- [ ] Привилегированные kernel-команды и последующие deploy/poller операции используют sudo.
- [ ] Невалидные логины и shell-инъекции отклоняются HTTP 400.
- [ ] UI/SSE показывают фактический `user@host`; пароль не раскрывается.
- [ ] Независимый review, `just ci`, push CI и production deploy успешны.
