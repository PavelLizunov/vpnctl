use std::net::IpAddr;

use maud::{DOCTYPE, Markup, html};

pub(super) const CSS: &str = concat!(
    include_str!("../../assets/css/theme.css"),
    include_str!("../../assets/corp-portal/corp.css")
);
pub(super) const DIAGNOSTICS_JS: &str =
    include_str!("../../assets/corp-portal/corp-diagnostics.js");
pub(super) const PHONE_JS: &str = include_str!("../../assets/corp-portal/corp-phone.js");
pub(super) const JS: &str = include_str!("../../assets/corp-portal/corp.js");

fn page(title: &str, body: &Markup) -> String {
    html! {
        (DOCTYPE)
        html lang="ru" {
            head {
                meta charset="utf-8";
                meta name="viewport" content="width=device-width, initial-scale=1";
                meta name="robots" content="noindex, nofollow";
                title { (title) " · Corp · vpnctl" }
                link rel="stylesheet" href="/assets/corp.css";
                script src="/assets/corp.js" defer {}
                script src="/assets/corp-phone.js" defer {}
            }
            body {
                header.corp-masthead {
                    div.corp-identity {
                        span.corp-product { "VPNRouter" }
                        span { "Corp · корпоративный VPN" }
                    }
                }
                (body)
            }
        }
    }
    .into_string()
}

pub(super) fn login(error: Option<&str>) -> String {
    login_for(error, "")
}

pub(super) fn login_for(error: Option<&str>, username: &str) -> String {
    page(
        "Вход",
        &html! {
            main.access-page {
                section.card aria-labelledby="page-title" {
                    p.eyebrow { "Корпоративные правила" }
                    h1 id="page-title" { "Вход" }
                    p.muted { "Введите username и пароль своей компании." }
                    @if let Some(message) = error {
                        p.notice.error role="alert" { (message) }
                    }
                    form method="post" action="https://admin.corp.ninitux.com/login" {
                        label for="username" { "Username компании" }
                        input id="username" name="username" type="text" value=(username)
                            autocomplete="username" maxlength="64" required autofocus;
                        label for="password" { "Пароль" }
                        input id="password" name="password" type="password"
                            autocomplete="current-password" required;
                        button.primary type="submit" { "Войти" }
                    }
                }
                p.access-note { "VPN должен оставаться подключённым, пока вы меняете правила." }
            }
        },
    )
}

pub(super) fn vpn_required(ip: Option<IpAddr>) -> String {
    page(
        "Подключите VPN",
        &html! {
            main.access-page {
                section.card aria-labelledby="page-title" {
                    p.eyebrow { "Корпоративные правила" }
                    h1 id="page-title" { "Подключите корпоративный VPN" }
                    p.muted { "Эта страница доступна через корпоративное подключение." }
                    ol.steps {
                        li { "Откройте приложение VPN." }
                        li { "Выберите корпоративное подключение и включите VPN." }
                        li { "Вернитесь сюда и попробуйте снова." }
                    }
                    @if let Some(address) = ip {
                        p.observed-ip { "Ваш адрес: " span { (address) } }
                    }
                    a.button.primary href="/" { "Проверить подключение" }
                    p.muted.small { "Если VPN уже подключён, а страница недоступна, обратитесь к администратору." }
                }
            }
        },
    )
}

pub(super) fn unavailable() -> String {
    page(
        "Страница недоступна",
        &html! {
            main.access-page {
                section.card aria-labelledby="page-title" {
                    p.eyebrow { "Корпоративные правила" }
                    h1 id="page-title" { "Страница пока недоступна" }
                    p.muted { "Управление корпоративными правилами сейчас недоступно. Попробуйте позже или обратитесь к администратору." }
                    a.button.primary href="/" { "Попробовать снова" }
                }
            }
        },
    )
}

pub(super) fn editor(username: &str) -> String {
    page(
        "Корпоративные правила",
        &html! {
            main.editor id="corp-editor" data-username=(username) aria-busy="true" {
                header.page-header {
                    div {
                        h1 { "Корпоративные правила" }
                        p.muted { "Выберите, как открывать сайты: напрямую или через VPN." }
                    }
                    button.quiet.editor-control id="logout" type="button" disabled { "Выйти" }
                }
                nav.portal-nav aria-label="Разделы" {
                    a href="/" aria-current="page" { "Правила" }
                    a href="/diagnostics" { "Диагностика" }
                }
                noscript {
                    p.notice.error { "Для изменения правил включите JavaScript в браузере и обновите страницу." }
                }
                div.status-panel {
                    p id="status" role="status" aria-live="polite" { "Загружаем правила…" }
                    p.muted.small id="draft-status" { "Изменения появятся у пользователей после сохранения." }
                }
                p.notice.error id="error" role="alert" hidden {}
                div.notice id="reload-notice" hidden {
                    p id="reload-message" {}
                    button.editor-control id="reload" type="button" { "Загрузить актуальные правила" }
                }
                a.button id="session-link" href="/" hidden { "Вернуться ко входу" }
                section.card aria-labelledby="add-title" {
                    h2 id="add-title" { "Добавить сайт" }
                    p.muted.small { "Можно вставить адрес сайта или ссылку на страницу. Перед добавлением покажем адрес правила." }
                    form id="add-form" {
                        div.add-fields {
                            div.field {
                                label for="site" { "Сайт или ссылка" }
                                input.editor-control id="site" type="text" placeholder="example.com"
                                    autocomplete="off" autocapitalize="none" spellcheck="false" maxlength="4096" required disabled;
                            }
                            button.editor-control id="normalize" type="submit" disabled { "Проверить адрес" }
                        }
                    }
                    div.preview id="site-preview" hidden {
                        p { "Будет добавлен сайт: " strong id="normalized-site" {} }
                        p.muted.small { "Правило действует и для его поддоменов." }
                        div.preview-fields {
                            div.field {
                                label for="new-action" { "Как открывать" }
                                select.editor-control.route-choice id="new-action" data-action="direct"
                                    aria-describedby="new-route-hint" disabled {
                                    option value="direct" { "Напрямую" }
                                    option value="proxy" { "Через VPN" }
                                }
                                p.route-hint id="new-route-hint" { "Без VPN, через ваш интернет" }
                            }
                            div.field {
                                label for="new-comment" { "Комментарий" }
                                input.editor-control id="new-comment" type="text" maxlength="256" placeholder="Необязательно" disabled;
                            }
                            button.primary.editor-control id="add-site" type="button" disabled { "Добавить в список" }
                        }
                    }
                }
                section.card.rules-card aria-labelledby="rules-title" {
                    div.section-heading {
                        h2 id="rules-title" { "Список сайтов" }
                        p.muted.small id="rule-count" {}
                    }
                    dl.route-guide {
                        div {
                            dt { "Напрямую — без VPN" }
                            dd { "Сайт открывается через ваш обычный интернет." }
                        }
                        div {
                            dt { "Через VPN" }
                            dd { "Сайт открывается через корпоративный VPN-сервер." }
                        }
                    }
                    p.muted.small.route-note { "Сам Corp VPN оставьте включённым: здесь вы выбираете путь только для сайта." }
                    label for="search" { "Поиск по сайту или комментарию" }
                    input.editor-control id="search" type="search" placeholder="Найти сайт…" autocomplete="off" disabled;
                    table.rules-table {
                        caption.sr-only { "Сайты и их маршруты. Изменения нужно сохранить." }
                        thead {
                            tr {
                                th scope="col" { "Сайт" }
                                th scope="col" { "Как открывать" }
                                th scope="col" { "Комментарий" }
                                th scope="col" { span.sr-only { "Действия" } }
                            }
                        }
                        tbody id="rules" {}
                    }
                    p.empty id="empty-list" hidden {}
                    div.save-bar {
                        div {
                            p.save-title { "Сохранить весь список" }
                            p.muted.small { "По умолчанию новые правила начнут действовать при следующем подключении VPN." }
                        }
                        div.actions {
                            button.primary.editor-control id="save" type="button" disabled { "Сохранить правила" }
                            button.editor-control id="save-now" type="button" disabled { "Применить сейчас…" }
                        }
                    }
                }
                details.card id="history-panel" {
                    summary { "История изменений" }
                    p.muted.small { "Можно вернуть прежний список. Он сохранится как новая версия." }
                    button.editor-control id="refresh-history" type="button" disabled { "Обновить историю" }
                    p.muted id="history-status" role="status" { "Откройте историю, чтобы увидеть сохранённые списки." }
                    ol.history-list id="history" {}
                }
                dialog id="confirm-dialog" aria-labelledby="confirm-title" aria-describedby="confirm-description" {
                    h2 id="confirm-title" {}
                    p id="confirm-description" {}
                    div id="restore-timing" hidden {
                        label for="confirm-timing" { "Когда применить" }
                        select id="confirm-timing" {
                            option value="next_connection" { "При следующем подключении VPN" }
                            option value="now" { "Сейчас" }
                        }
                    }
                    div.notice.warning id="interrupt-warning" hidden {
                        p { "У тех, кто сейчас подключён, VPN может ненадолго прерваться. Остановленный VPN останется выключенным." }
                        label.check-label for="confirm-interrupt" {
                            input id="confirm-interrupt" type="checkbox";
                            span { "Подтверждаю применение сейчас и возможный перерыв связи" }
                        }
                    }
                    div.dialog-actions {
                        button id="cancel-confirm" type="button" { "Отмена" }
                        button.primary id="accept-confirm" type="button" { "Подтвердить" }
                    }
                }
            }
        },
    )
}

pub(super) fn diagnostics(csrf: &str, username: &str) -> String {
    page(
        "Диагностика",
        &html! {
            script src="/assets/corp-diagnostics.js" defer {}
            main.editor id="corp-diagnostics" data-username=(username) data-csrf=(csrf) {
                header.page-header {
                    div { h1 { "Диагностика" }
                        p.muted { "Выберите отчёт: сначала покажем вывод и что сделать, подробности можно раскрыть ниже." }
                    }
                    button id="diagnostics-logout" type="button" { "Выйти" }
                }
                nav.portal-nav aria-label="Разделы" {
                    a href="/" { "Правила" }
                    a href="/diagnostics" aria-current="page" { "Диагностика" }
                }
                noscript { p.notice.error { "Чтобы просмотреть отчёты, включите JavaScript и обновите страницу." } }
                p id="diagnostics-status" role="status" aria-live="polite" { "Загружаем отчёты…" }
                p.notice.error id="diagnostics-error" role="alert" hidden {}
                a.button href="/diagnostics" id="diagnostics-login" hidden { "Войти снова" }
                div.actions { button id="diagnostics-refresh" type="button" { "Обновить список" } }
                div.diagnostics-layout {
                    section.card aria-labelledby="reports-title" {
                        h2 id="reports-title" { "Полученные отчёты" }
                        p.muted.small { "Названия устройств берём из приложения." }
                        ul.report-list id="diagnostics-list" {}
                        button id="diagnostics-more" type="button" hidden { "Ещё отчёты" }
                    }
                    section.card id="diagnostics-detail" aria-labelledby="diagnostics-detail-title" tabindex="-1" {
                        h2 id="diagnostics-detail-title" { "Выберите отчёт" }
                        div id="diagnostics-detail-body" { p.muted { "Здесь появится короткий ответ и следующий шаг." } }
                    }
                }
            }
        },
    )
}
