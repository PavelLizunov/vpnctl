use super::{OperatorState, Result, unavailable};
use axum::{
    http::{HeaderMap, StatusCode},
    response::{Html, IntoResponse, Response},
};
use maud::{DOCTYPE, html};

use crate::handlers::admin::{helpers::theme_accent, ui::root_class};

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
pub(super) fn reveal(password: &str, company_id: &str, username: &str) -> Response {
    reveal_result(password, company_id, username, None)
}
pub(super) fn reveal_setup(
    password: &str,
    company_id: &str,
    username: &str,
    support_ready: bool,
) -> Response {
    reveal_result(password, company_id, username, Some(support_ready))
}
fn reveal_result(
    password: &str,
    company_id: &str,
    username: &str,
    support_ready: Option<bool>,
) -> Response {
    let company_url = company_url(company_id);
    let support_status = match support_ready {
        Some(true) => "<p>Диагностика компании настроена.</p>".to_owned(),
        Some(false) => format!(
            "<p role=\"status\">Компания создана, но настройка диагностики не завершилась. Пароль ниже действует; сохраните его сейчас.</p><p><a href=\"{}#company-diagnostics\">Повторить настройку диагностики</a>: откройте компанию и нажмите «Скачать настройки диагностики». Новый пароль создавать не нужно.</p>",
            escape(&company_url)
        ),
        None => String::new(),
    };
    Html(document("Пароль создан", &format!("<section><h2>Сохраните пароль сейчас</h2><p>Username компании: <strong>{}</strong></p>{support_status}<p>Пароль показывается только один раз. Передайте его разрешённым сотрудникам по защищённому каналу.</p><code id=\"corp-generated-password\">{}</code><p>Повторное открытие страницы не восстановит пароль. Если ответ потерян, сначала проверьте состояние, затем выполните новую ротацию.</p><a href=\"{}\">Продолжить</a></section>", escape(username), escape(password), escape(&company_url)))).into_response()
}

fn form(
    company_id: &str,
    action: &str,
    csrf: &str,
    version: Option<u64>,
    fields: &str,
    label: &str,
) -> String {
    actionable_form(company_id, action, csrf, version, fields, label, true)
}
fn actionable_form(
    company_id: &str,
    action: &str,
    csrf: &str,
    version: Option<u64>,
    fields: &str,
    label: &str,
    available: bool,
) -> String {
    let company = if company_id.is_empty() {
        String::new()
    } else {
        format!(
            "<input type=\"hidden\" name=\"company_id\" value=\"{}\">",
            escape(company_id)
        )
    };
    let version = version
        .map(|version| {
            format!("<input type=\"hidden\" name=\"expected_config_version\" value=\"{version}\">")
        })
        .unwrap_or_default();
    format!(
        "<form method=\"post\" action=\"/admin/corp/{action}\"><input type=\"hidden\" name=\"csrf\" value=\"{}\">{company}{version}{fields}<button type=\"submit\"{}>{}</button></form>",
        escape(csrf),
        if available { "" } else { " disabled" },
        escape(label)
    )
}
const CONFIRM: &str = "<label class=\"confirm\"><input type=\"checkbox\" name=\"confirm\" value=\"true\" required>Подтверждаю операцию</label>";

pub(super) async fn page(state: &OperatorState, headers: &HeaderMap) -> Result<Response> {
    let companies = state
        .app
        .inv
        .corp_companies()
        .await
        .map_err(|_| unavailable())?;
    if companies.len() == 1 {
        return page_for(state, &companies[0].company_id).await;
    }
    company_list(state, headers).await
}

pub(super) fn company_url(company_id: &str) -> String {
    format!("/admin/corp/company/{company_id}")
}

pub(super) async fn company_list(state: &OperatorState, headers: &HeaderMap) -> Result<Response> {
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
    let companies = state
        .app
        .inv
        .corp_companies()
        .await
        .map_err(|_| unavailable())?;
    let users = state
        .app
        .inv
        .list_users()
        .await
        .map_err(|_| unavailable())?;
    let available_users: Vec<_> = users
        .iter()
        .filter(|user| {
            !user.disabled
                && !companies
                    .iter()
                    .any(|company| company.status.user_id == user.id)
        })
        .collect();
    let (theme, accent) = theme_accent(headers);
    let root = format!("{} corp-companies", root_class(&theme, &accent));
    let title = "Корпоративные клиенты";
    let body = html! {
        (DOCTYPE)
        html lang="ru" {
            head {
                meta charset="utf-8";
                meta name="viewport" content="width=device-width, initial-scale=1";
                title { (title) }
                link rel="stylesheet" href="/admin/assets/css/theme.css";
                link rel="stylesheet" href="/admin/assets/css/components.css";
                link rel="stylesheet" href="/admin/corp/assets/operator.css";
            }
            body class=(root) {
                header.ed-tb {
                    a.ed-tb__logo href="/admin/" aria-label="Панель оператора" { "vpnctl" }
                    nav.ed-tb__nav aria-label="Разделы админки" {
                        a.on href="/admin/corp/companies" aria-current="page" { "Компании" }
                    }
                }
                main.ed-main {
                    h1.ed-art-h1 { (title) }
                    p.ed-art-deck { "У каждой компании свой username, пароль, правила и диагностика." }
                    section aria-label="Список компаний" {
                        @if companies.is_empty() {
                            p { "Компаний пока нет. " a href="#company-setup" { "Добавить компанию" } }
                        } @else {
                            table.ed-grid aria-label=(title) {
                                thead {
                                    tr {
                                        th scope="col" { "Username" }
                                        th scope="col" { "Доступ" }
                                        th scope="col" { "Правила" }
                                        th scope="col" { span.ed-sr-only { "Действие" } }
                                    }
                                }
                                tbody {
                                    @for company in &companies {
                                        tr {
                                            td { (company.status.user_id.0) }
                                            td { (if company.status.enabled { "Включён" } else { "Выключен" }) }
                                            td { "Версия " (company.status.revision) }
                                            td { a href=(company_url(&company.company_id)) { "Настроить компанию" } }
                                        }
                                    }
                                }
                            }
                        }
                    }
                    section id="company-setup" {
                        div.ed-section-h { h2 { "Добавить компанию" } }
                        p { "Выберите существующую корпоративную подписку. Пароль компании будет отдельным от пароля оператора." }
                        @if available_users.is_empty() {
                            p { "Все доступные пользователи уже привязаны. "
                                a href="/admin/users" { "Создать подписку" }
                            }
                        } @else {
                            form method="post" action="/admin/corp/setup" {
                                input type="hidden" name="csrf" value=(csrf);
                                label {
                                    "Username подписки"
                                    select name="user_id" required {
                                        @for user in available_users {
                                            option value=(user.id.0) { (user.id.0) }
                                        }
                                    }
                                }
                                label.confirm {
                                    input type="checkbox" name="confirm_binding" value="true" required;
                                    "Подтверждаю постоянную привязку компании к подписке"
                                }
                                button.ed-abtn.ed-abtn--primary type="submit" { "Создать компанию" }
                            }
                        }
                    }
                }
            }
        }
    };
    Ok(Html(body.into_string()).into_response())
}

pub(super) async fn page_for(state: &OperatorState, company_id: &str) -> Result<Response> {
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
    let store = state.app.inv.corp_for(company_id);
    let record = store.corp_record().await.map_err(|_| unavailable())?;
    let record = record.ok_or_else(|| super::fail(StatusCode::NOT_FOUND))?;
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
    let verified = store
        .corp_verified_egress()
        .await
        .map_err(|_| unavailable())?;
    let now = (config.clock)();
    let provider_available = state.app.corp_egress.available();
    let enable_ready = provider_available
        && state
            .app
            .corp_egress
            .ready_to_enable_for(&state.app, company_id, status.config_version)
            .await
            .unwrap_or(false);
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
        let attempt_label = match state
            .app
            .corp_egress
            .attempt_for(company_id, &server.server_id)
            .state
        {
            crate::corp_egress::AttemptState::Idle => "Проверка ещё не запускалась",
            crate::corp_egress::AttemptState::Running => {
                "Проверка выполняется. Обновите состояние через некоторое время"
            }
            crate::corp_egress::AttemptState::Verified => "Проверка завершена, результат сохранён",
            crate::corp_egress::AttemptState::Failed => {
                "Проверка не удалась. Можно повторить попытку"
            }
            crate::corp_egress::AttemptState::Conflict => {
                "Конфигурация изменилась. Проверьте состояние и повторите попытку"
            }
            crate::corp_egress::AttemptState::Unavailable => {
                "Проверка временно недоступна. Повторите попытку позднее"
            }
        };
        server_rows.push_str(&format!(
            "<li><h3>{}</h3><p>Сохранённое подтверждение: {state_label}</p><p>Последняя попытка: {attempt_label}</p>{}</li>",
            escape(&server.label),
            actionable_form(company_id,
                "probe",
                &csrf,
                version,
                &format!(
                    "<input type=\"hidden\" name=\"server_id\" value=\"{}\">",
                    escape(&server.server_id.0)
                ),
                if provider_available {
                    "Проверить выход"
                } else {
                    "Проверить выход (недоступно)"
                },
                provider_available,
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
    body.insert_str(
        0,
        "<p><a href=\"/admin/corp/companies\">Все компании</a></p>",
    );
    body.push_str("<section><h2>Доступ</h2>");
    if !provider_available {
        body.push_str("<p>Включение недоступно: механизм проверки выхода не подключён.</p>");
    } else if !enable_ready {
        body.push_str("<p>Для включения нужен доступный пользователь и актуальное подтверждение выхода. Запустите проверку сервера и обновите состояние.</p>");
    }
    body.push_str(&actionable_form(
        company_id,
        "enabled",
        &csrf,
        version,
        &format!("<input type=\"hidden\" name=\"enabled\" value=\"true\">{CONFIRM}"),
        "Включить доступ",
        enable_ready,
    ));
    body.push_str(&form(
        company_id,
        "enabled",
        &csrf,
        version,
        &format!("<input type=\"hidden\" name=\"enabled\" value=\"false\">{CONFIRM}"),
        "Отключить доступ",
    ));
    body.push_str(&form(
        company_id,
        "sessions/revoke",
        &csrf,
        version,
        CONFIRM,
        "Завершить все корпоративные сессии",
    ));
    body.push_str("</section><section><h2>Пароль сотрудников</h2><p>Новый пароль сразу заменяет прежний и завершает сессии. Старый пароль больше не принимается.</p>");
    body.push_str(&form(
        company_id,
        "password/rotate",
        &csrf,
        version,
        CONFIRM,
        "Создать новый пароль",
    ));
    body.push_str("</section><section><h2>Доступ клиентов к политике</h2><p>Порядок ротации: добавить → выгрузить и перенести → удалить прежний. Файл содержит секрет доступа. Вставьте объект business.policy в сохранённый полный частный комплект. Это не самостоятельный файл импорта сотрудника и не замена VPN-подписки.</p>");
    body.push_str(&form(
        company_id,
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
            company_id,
            "export",
            &csrf,
            version,
            &id,
            "Скачать business.policy",
        ));
        body.push_str(&form(
            company_id,
            "readers/remove",
            &csrf,
            version,
            &format!("{id}{CONFIRM}"),
            "Удалить доступ клиента",
        ));
        body.push_str("</article>");
    }
    body.push_str("</section><section id=\"company-diagnostics\"><h2>Диагностика компании</h2><p>Настройки относятся только к этой компании и добавляются в её частный комплект клиента.</p>");
    body.push_str(&form(
        company_id,
        "support/export",
        &csrf,
        version,
        "",
        "Скачать настройки диагностики",
    ));
    body.push_str("</section><section><h2>Ключи подписи</h2><p>Добавьте ключ, выгрузите доверие и перенесите его клиентам, затем активируйте. Отключённые клиенты могут ещё не знать новый ключ. Активация влияет на следующую публикацию и не переподписывает текущие правила. Используемые историей ключи удалить нельзя.</p>");
    body.push_str(&form(
        company_id,
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
                company_id,
                "signers/activate",
                &csrf,
                version,
                &id,
                "Активировать ключ",
            ));
            body.push_str(&form(
                company_id,
                "signers/remove",
                &csrf,
                version,
                &id,
                "Удалить ключ, если это безопасно",
            ));
        }
        body.push_str("</article>");
    }
    body.push_str("</section><section><h2>Проверка серверов</h2>");
    if !provider_available {
        body.push_str(
            "<p>Проверка недоступна до подключения доверенного механизма подтверждения выхода.</p>",
        );
    }
    body.push_str("<p>Проверка продолжается после закрытия страницы. Неуспешная попытка не обновляет сохранённые результаты.</p><p><a href=\"/admin/corp\">Обновить состояние проверки</a></p><ul>");
    body.push_str(&server_rows);
    if server_rows.is_empty() {
        body.push_str("<li>Нет подходящих серверов</li>");
    }
    body.push_str("</ul></section><p>Если операция завершилась ошибкой или ответ потерян, загрузите текущее состояние перед новой попыткой. Потерянный пароль требует новой ротации.</p>");
    body = body.replace(
        "href=\"/admin/corp\"",
        &format!("href=\"{}\"", escape(&company_url(company_id))),
    );
    body = body.replace(
        "Подтверждаю операцию",
        &format!(
            "Подтверждаю операцию для компании {}",
            escape(&status.user_id.0)
        ),
    );
    Ok((
        StatusCode::OK,
        Html(document(&format!("Компания: {}", status.user_id.0), &body)),
    )
        .into_response())
}
