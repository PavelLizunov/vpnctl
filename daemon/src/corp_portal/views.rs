use std::net::IpAddr;

use maud::{DOCTYPE, Markup, html};

pub(super) const CSS: &str = include_str!("../../assets/corp-portal/corp.css");
pub(super) const JS: &str = include_str!("../../assets/corp-portal/corp.js");

fn page(title: &str, body: &Markup) -> String {
    html! {
        (DOCTYPE)
        html lang="ru" {
            head {
                meta charset="utf-8";
                meta name="viewport" content="width=device-width, initial-scale=1";
                meta name="robots" content="noindex, nofollow";
                title { (title) " · Corp" }
                link rel="stylesheet" href="/assets/corp.css";
                script src="/assets/corp.js" defer {}
            }
            body { (body) }
        }
    }
    .into_string()
}

pub(super) fn login(error: Option<&str>) -> String {
    page(
        "Вход",
        &html! {
            main.access-page {
                p.brand { "Corp" }
                section.card aria-labelledby="page-title" {
                    p.eyebrow { "Корпоративные правила" }
                    h1 id="page-title" { "Вход" }
                    p.muted { "Введите пароль, чтобы управлять маршрутами сайтов." }
                    @if let Some(message) = error {
                        p.notice.error role="alert" { (message) }
                    }
                    form method="post" action="https://admin.corp.ninitux.com/login" {
                        label for="password" { "Пароль" }
                        input id="password" name="password" type="password"
                            autocomplete="current-password" required autofocus;
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
                p.brand { "Corp" }
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
                p.brand { "Corp" }
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

pub(super) fn editor() -> String {
    page(
        "Корпоративные правила",
        &html! {
            main.editor id="corp-editor" aria-busy="true" {
                header.page-header {
                    div {
                        p.brand { "Corp" }
                        h1 { "Корпоративные правила" }
                        p.muted { "Выберите, как открывать сайты: напрямую или через VPN." }
                    }
                    button.quiet.editor-control id="logout" type="button" disabled { "Выйти" }
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
                                label for="new-action" { "Маршрут" }
                                select.editor-control id="new-action" disabled {
                                    option value="direct" { "Без VPN" }
                                    option value="proxy" { "Через VPN" }
                                }
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
                    label for="search" { "Поиск по сайту или комментарию" }
                    input.editor-control id="search" type="search" placeholder="Найти сайт…" autocomplete="off" disabled;
                    table.rules-table {
                        caption.sr-only { "Сайты и их маршруты. Изменения нужно сохранить." }
                        thead {
                            tr {
                                th scope="col" { "Сайт" }
                                th scope="col" { "Маршрут" }
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
