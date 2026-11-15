use super::{OperatorState, Result, unavailable};
use axum::{
    http::StatusCode,
    response::{Html, IntoResponse, Response},
};

pub(super) fn escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}
pub(super) fn document(title: &str, body: &str) -> String {
    format!(
        "<!doctype html><html lang=\"ru\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>{}</title><link rel=\"stylesheet\" href=\"/admin/corp/assets/operator.css\"></head><body><main><nav><a href=\"/admin/\">Панель оператора</a> · <a href=\"/admin/corp\">Корпоративная политика</a></nav><h1>{}</h1>{body}</main></body></html>",
        escape(title),
        escape(title)
    )
}
pub(super) fn reveal(password: &str) -> Response {
    Html(document("Пароль создан", &format!("<section><h2>Сохраните пароль сейчас</h2><p>Пароль показывается только один раз. Передайте его разрешённым сотрудникам по защищённому каналу.</p><code id=\"corp-generated-password\">{}</code><p>Повторное открытие страницы не восстановит пароль. Если ответ потерян, сначала проверьте состояние, затем выполните новую ротацию.</p><a href=\"/admin/corp\">Продолжить</a></section>", escape(password)))).into_response()
}
fn form(action: &str, csrf: &str, version: Option<u64>, fields: &str, label: &str) -> String {
    let version = version
        .map(|version| {
            format!("<input type=\"hidden\" name=\"expected_config_version\" value=\"{version}\">")
        })
        .unwrap_or_default();
    format!(
        "<form method=\"post\" action=\"/admin/corp/{action}\"><input type=\"hidden\" name=\"csrf\" value=\"{}\">{version}{fields}<button type=\"submit\">{}</button></form>",
        escape(csrf),
        escape(label)
    )
}
const CONFIRM: &str = "<label class=\"confirm\"><input type=\"checkbox\" name=\"confirm\" value=\"true\" required>Подтверждаю операцию</label>";

pub(super) async fn page(state: &OperatorState) -> Result<Response> {
    let config = &state.config;
    let csrf = config
        .auth
        .as_ref()
        .ok_or_else(unavailable)?
        .operator_csrf(
            config.origin.as_deref().ok_or_else(unavailable)?,
            (config.clock)(),
        )
        .ok_or_else(unavailable)?;
    let record = state
        .app
        .inv
        .corp_record()
        .await
        .map_err(|_| unavailable())?;
    let Some(record) = record else {
        let users = state
            .app
            .inv
            .list_users()
            .await
            .map_err(|_| unavailable())?;
        let mut options = String::new();
        for user in users.iter().filter(|user| !user.disabled) {
            options.push_str(&format!(
                "<option value=\"{}\">{}</option>",
                escape(&user.id.0),
                escape(&user.id.0)
            ));
        }
        let fields = format!(
            "<label>Пользователь<select name=\"user_id\" required>{options}</select></label><label class=\"confirm\"><input type=\"checkbox\" name=\"confirm_binding\" value=\"true\" required>Подтверждаю постоянную привязку: заменить пользователя впоследствии нельзя</label>"
        );
        return Ok(Html(document("Корпоративная политика", &format!("<section><h2>Привязка отсутствует</h2><p>Выберите существующего включённого пользователя. Настройка создаёт выключенную привязку без опубликованных правил.</p>{}</section>", form("setup", &csrf, None, &fields, "Создать привязку")))).into_response());
    };
    let status = &record.status;
    let version = Some(status.config_version);
    let user = state
        .app
        .inv
        .get_user(&status.user_id)
        .await
        .map_err(|_| unavailable())?;
    let availability = match user {
        None => "Пользователь отсутствует",
        Some(ref user) if user.disabled => "Пользователь отключён",
        Some(_) => "Пользователь доступен",
    };
    let servers = crate::corp_portal::eligibility::eligible_servers(&state.app, &status.user_id)
        .await
        .map_err(|_| unavailable())?;
    let verified = state
        .app
        .inv
        .corp_verified_egress()
        .await
        .map_err(|_| unavailable())?;
    let now = (config.clock)();
    let mut server_rows = String::new();
    let mut ready = false;
    for server in servers {
        let entries: Vec<_> = verified
            .iter()
            .filter(|entry| entry.server_id == server.server_id)
            .collect();
        let fresh = |entry: &&vpnctl_inventory::CorpVerifiedEgress| {
            entry.verified_at > 0 && entry.verified_at <= now && now - entry.verified_at <= 86400
        };
        let state_label = if entries.is_empty() {
            "Не проверен"
        } else if entries.iter().any(|entry| {
            entry.configuration_fingerprint == server.configuration_fingerprint && fresh(entry)
        }) {
            ready = true;
            "Готов: подтверждение выхода актуально"
        } else if entries
            .iter()
            .all(|entry| entry.configuration_fingerprint != server.configuration_fingerprint)
        {
            "Конфигурация изменена"
        } else {
            "Проверка устарела"
        };
        server_rows.push_str(&format!(
            "<li><h3>{}</h3><p>{state_label}</p>{}</li>",
            escape(&server.label),
            form(
                "probe",
                &csrf,
                version,
                &format!(
                    "<input type=\"hidden\" name=\"server_id\" value=\"{}\">",
                    escape(&server.server_id.0)
                ),
                "Проверить выход (недоступно)"
            )
        ));
    }
    let overall = if user.is_none() {
        "Пользователь отсутствует"
    } else if user.as_ref().is_some_and(|user| user.disabled) {
        "Пользователь отключён"
    } else if !status.enabled {
        "Выключено"
    } else if ready {
        "Готово по сохранённым подтверждениям"
    } else {
        "Нет актуального подтверждения выхода"
    };
    let mut body = format!(
        "<section><h2>Текущее состояние: {overall}</h2><dl><dt>Пользователь (постоянная привязка)</dt><dd>{}</dd><dt>Доступность</dt><dd>{availability}</dd><dt>Доступ</dt><dd>{}</dd><dt>Идентификатор политики</dt><dd>{}</dd><dt>Редакция</dt><dd>{}</dd><dt>Версия конфигурации</dt><dd>{}</dd><dt>Активный ключ</dt><dd>{}</dd></dl><p>Готовность сервера не подтверждает, что клиенты получили или применили настройки.</p></section>",
        escape(&status.user_id.0),
        if status.enabled {
            "Включён"
        } else {
            "Выключен"
        },
        escape(&status.policy_id),
        status.revision,
        status.config_version,
        escape(&status.active_key_id)
    );
    if status.revision == 0 {
        body.push_str("<p>Правила ещё не опубликованы (редакция 0).</p>");
    }
    body.push_str("<section><h2>Доступ</h2><p>Включение заблокировано: проверка фактического выхода TCP/UDP ещё не реализована.</p><button type=\"button\" disabled>Включить доступ</button>");
    body.push_str(&form(
        "enabled",
        &csrf,
        version,
        &format!("<input type=\"hidden\" name=\"enabled\" value=\"false\">{CONFIRM}"),
        "Отключить доступ",
    ));
    body.push_str(&form(
        "sessions/revoke",
        &csrf,
        version,
        CONFIRM,
        "Завершить все корпоративные сессии",
    ));
    body.push_str("</section><section><h2>Пароль сотрудников</h2><p>Новый пароль сразу заменяет прежний и завершает сессии. Старый пароль больше не принимается.</p>");
    body.push_str(&form(
        "password/rotate",
        &csrf,
        version,
        CONFIRM,
        "Создать новый пароль",
    ));
    body.push_str("</section><section><h2>Доступ клиентов к политике</h2><p>Порядок ротации: добавить → выгрузить и перенести → удалить прежний. Файл содержит секрет доступа. Вставьте объект business.policy в сохранённый полный частный комплект. Это не самостоятельный файл импорта сотрудника и не замена VPN-подписки.</p>");
    body.push_str(&form(
        "readers/add",
        &csrf,
        version,
        "",
        "Добавить доступ для клиента",
    ));
    for reader in &record.credentials.reader_tokens {
        body.push_str(&format!("<article><h3>Клиент: {}</h3>", escape(&reader.id)));
        let id = format!(
            "<input type=\"hidden\" name=\"reader_id\" value=\"{}\">",
            escape(&reader.id)
        );
        body.push_str(&form(
            "export",
            &csrf,
            version,
            &id,
            "Скачать business.policy",
        ));
        body.push_str(&form(
            "readers/remove",
            &csrf,
            version,
            &format!("{id}{CONFIRM}"),
            "Удалить доступ клиента",
        ));
        body.push_str("</article>");
    }
    body.push_str("</section><section><h2>Ключи подписи</h2><p>Добавьте ключ, выгрузите доверие и перенесите его клиентам, затем активируйте. Отключённые клиенты могут ещё не знать новый ключ. Активация влияет на следующую публикацию и не переподписывает текущие правила. Используемые историей ключи удалить нельзя.</p>");
    body.push_str(&form(
        "signers/add",
        &csrf,
        version,
        "",
        "Добавить неактивный ключ",
    ));
    for key in &record.credentials.signing_keys {
        body.push_str(&format!(
            "<article><h3>Ключ: {}</h3><p>{}</p>",
            escape(&key.id),
            if key.id == record.credentials.active_key_id {
                "Активный"
            } else {
                "Неактивный"
            }
        ));
        let id = format!(
            "<input type=\"hidden\" name=\"key_id\" value=\"{}\">{CONFIRM}",
            escape(&key.id)
        );
        if key.id != record.credentials.active_key_id {
            body.push_str(&form(
                "signers/activate",
                &csrf,
                version,
                &id,
                "Активировать ключ",
            ));
            body.push_str(&form(
                "signers/remove",
                &csrf,
                version,
                &id,
                "Удалить ключ, если это безопасно",
            ));
        }
        body.push_str("</article>");
    }
    body.push_str("</section><section><h2>Проверка серверов</h2><p>Проверка недоступна до подключения доверенного механизма подтверждения выхода. Неуспешная попытка не обновляет сохранённые результаты.</p><ul>");
    body.push_str(&server_rows);
    if server_rows.is_empty() {
        body.push_str("<li>Нет подходящих серверов</li>");
    }
    body.push_str("</ul></section><p>Если операция завершилась ошибкой или ответ потерян, загрузите текущее состояние перед новой попыткой. Потерянный пароль требует новой ротации.</p>");
    Ok((
        StatusCode::OK,
        Html(document("Корпоративная политика", &body)),
    )
        .into_response())
}
