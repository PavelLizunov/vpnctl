//! Contract-derived tests. Fixtures never contact a public service.

#[cfg(test)]
#[path = "common/cheburcheck_http.rs"]
mod cheburcheck_http;

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod spec {
    use std::net::IpAddr;
    use std::time::Duration;

    use super::cheburcheck_http::{HttpFixture, HttpResponse};

    use vpnctld::cheburcheck::{
        Client, DynamicPhase, DynamicResult, FailureCode, ListResult, ProbeAccumulator,
        ProbeReport, Report, SseDecoder, SseEvent,
    };

    fn event(event: &str, data: &str) -> SseEvent {
        SseEvent {
            event: event.to_owned(),
            data: data.to_owned(),
        }
    }

    fn decode_chunks(chunks: &[&[u8]]) -> Vec<SseEvent> {
        let mut decoder = SseDecoder::new();
        chunks
            .iter()
            .flat_map(|chunk| decoder.push(chunk).expect("valid SSE chunk"))
            .collect()
    }

    #[test]
    fn decoder_accepts_every_single_byte_split_of_utf8_crlf_and_multiline_data() {
        let wire = "event: report\r\ndata: Москва\r\ndata: провайдер\r\n\r\n";
        let expected = vec![event("report", "Москва\nпровайдер")];
        for split in 0..=wire.len() {
            let bytes = wire.as_bytes();
            assert_eq!(
                decode_chunks(&[&bytes[..split], &bytes[split..]]),
                expected,
                "split at byte {split}"
            );
        }
        let bytes: Vec<&[u8]> = wire.as_bytes().chunks(1).collect();
        assert_eq!(decode_chunks(&bytes), expected);
    }

    #[test]
    fn decoder_accepts_lf_and_preserves_multiline_data() {
        assert_eq!(
            decode_chunks(&[b"event: started\ndata: first\ndata: second\n\n"]),
            vec![event("started", "first\nsecond")]
        );
    }

    #[test]
    fn decoder_ignores_comments_and_unknown_fields() {
        assert_eq!(
            decode_chunks(&[
                b": keepalive\r\n\r\nretry: 5000\r\nid: ignored\r\n",
                b"event: done\r\ndata: {}\r\n: inside event\r\n\r\n",
            ]),
            vec![event("done", "{}")]
        );
    }

    #[test]
    fn decoder_waits_for_the_event_terminator() {
        let mut decoder = SseDecoder::new();
        assert!(
            decoder
                .push(b"event: started\ndata: {}\n")
                .expect("incomplete event is buffered")
                .is_empty()
        );
        assert_eq!(
            decoder.push(b"\n").expect("event terminator"),
            vec![event("started", "{}")]
        );
    }

    #[test]
    fn decoder_returns_multiple_complete_events_in_order() {
        assert_eq!(
            decode_chunks(&[b"event: started\ndata: first\n\nevent: done\ndata: second\n\n"]),
            vec![event("started", "first"), event("done", "second")]
        );
    }

    #[test]
    fn decoder_rejects_invalid_utf8() {
        let mut decoder = SseDecoder::new();
        let failure = decoder
            .push(b"event: started\ndata: \xff\n\n")
            .expect_err("invalid UTF-8 cannot become an upstream event");
        assert_eq!(failure.code, FailureCode::InvalidResponse);
    }

    #[test]
    fn decoder_rejects_a_buffered_event_over_32_kib() {
        let mut decoder = SseDecoder::new();
        let mut wire = b"event: report\ndata: ".to_vec();
        wire.extend(vec![b'x'; 32 * 1024 + 1]);
        let failure = decoder
            .push(&wire)
            .expect_err("an unfinished event must have a bounded buffer");
        assert_eq!(failure.code, FailureCode::ResponseLimit);
    }

    #[test]
    fn decoder_rejects_a_complete_event_over_32_kib() {
        let mut decoder = SseDecoder::new();
        let mut wire = b"event: report\ndata: ".to_vec();
        wire.extend(vec![b'x'; 32 * 1024 + 1]);
        wire.extend_from_slice(b"\n\n");
        let failure = decoder
            .push(&wire)
            .expect_err("complete events are bounded too");
        assert_eq!(failure.code, FailureCode::ResponseLimit);
    }

    #[test]
    fn decoder_bounds_the_entire_stream_including_comments() {
        let mut decoder = SseDecoder::new();
        let comment = b": keepalive\n\n";
        let mut total = 0;
        loop {
            total += comment.len();
            match decoder.push(comment) {
                Ok(events) => {
                    assert!(events.is_empty());
                    assert!(total <= 512 * 1024, "SSE total limit was not enforced");
                }
                Err(failure) => {
                    assert_eq!(failure.code, FailureCode::ResponseLimit);
                    assert!(total > 512 * 1024, "stream was rejected below its limit");
                    break;
                }
            }
        }
    }

    #[test]
    fn unknown_events_do_not_change_accumulated_results() {
        let mut accumulator = ProbeAccumulator::new();
        let before = accumulator.snapshot();
        accumulator
            .apply("a_future_event", "not even JSON")
            .expect("unknown events are ignored");
        assert_eq!(accumulator.snapshot(), before);
    }

    #[test]
    fn malformed_known_events_fail_explicitly() {
        for event_name in ["started", "result", "done"] {
            let mut accumulator = ProbeAccumulator::new();
            let failure = accumulator
                .apply(event_name, "not JSON")
                .expect_err("known events must be parsed");
            assert_eq!(failure.code, FailureCode::InvalidResponse);
        }
    }

    fn result_payload(id: &str, verdict: &str, cached: bool) -> String {
        serde_json::json!({
            "probe_id": id,
            "cached": cached,
            "region": "Example",
            "provider": "Example ISP",
            "asn": "AS64500",
            "verdicts": [verdict],
            "target_hop": null,
            "dpi_hop": 2
        })
        .to_string()
    }

    #[test]
    fn duplicate_observers_are_ignored_and_missing_replies_are_not_blocks() {
        let mut accumulator = ProbeAccumulator::new();
        accumulator
            .apply("started", r#"{"online_probes":3}"#)
            .expect("started");
        accumulator
            .apply("result", &result_payload("one", "tspu_block", false))
            .expect("first observer");
        accumulator
            .apply("result", &result_payload("one", "ok", true))
            .expect("duplicate observer is ignored");
        accumulator
            .apply("result", &result_payload("two", "uncertain", true))
            .expect("second observer");
        accumulator
            .apply("done", r#"{"response_count":2,"online_probes":3}"#)
            .expect("done agrees with distinct replies and started total");
        let snapshot = accumulator.snapshot();
        assert_eq!(snapshot.phase, DynamicPhase::Done);
        assert_eq!(snapshot.reports.len(), 2);
        assert_eq!(snapshot.verdict_count("tspu_block"), 1);
        assert_eq!(snapshot.verdict_count("uncertain"), 1);
        assert_eq!(snapshot.verdict_count("ok"), 0);
        assert_eq!(snapshot.not_reported(), Some(1));
        assert!(!snapshot.reports[0].cached);
        assert!(snapshot.reports[1].cached);
    }

    #[test]
    fn contradictory_done_totals_cannot_complete_a_run() {
        for done in [
            r#"{"response_count":2,"online_probes":3}"#,
            r#"{"response_count":1,"online_probes":2}"#,
            r#"{"response_count":0,"online_probes":3}"#,
        ] {
            let mut accumulator = ProbeAccumulator::new();
            accumulator
                .apply("started", r#"{"online_probes":3}"#)
                .expect("started");
            accumulator
                .apply("result", &result_payload("one", "tspu_block", false))
                .expect("one distinct reply");
            let _ = accumulator.apply("done", done);
            assert_ne!(accumulator.snapshot().phase, DynamicPhase::Done, "{done}");
            assert_eq!(accumulator.snapshot().reports.len(), 1);
        }
    }

    #[test]
    fn zero_observers_are_unavailable_and_never_healthy() {
        let mut accumulator = ProbeAccumulator::new();
        let failure = match accumulator.apply("started", r#"{"online_probes":0}"#) {
            Err(failure) => failure,
            Ok(_) => accumulator
                .apply("done", r#"{"response_count":0,"online_probes":0}"#)
                .expect_err("no observers cannot produce a healthy result"),
        };
        assert_eq!(failure.code, FailureCode::NoObservers);
        assert_eq!(accumulator.snapshot().phase, DynamicPhase::Unavailable);
        assert!(accumulator.snapshot().reports.is_empty());
    }

    #[test]
    fn results_and_done_require_a_started_event() {
        for (event_name, data) in [
            ("result", result_payload("one", "ok", false)),
            (
                "done",
                r#"{"response_count":0,"online_probes":0}"#.to_owned(),
            ),
        ] {
            let mut accumulator = ProbeAccumulator::new();
            assert!(accumulator.apply(event_name, &data).is_err());
            assert_ne!(accumulator.snapshot().phase, DynamicPhase::Done);
        }
    }

    #[test]
    fn accumulator_caps_distinct_observers_at_256() {
        let mut accumulator = ProbeAccumulator::new();
        accumulator
            .apply("started", r#"{"online_probes":257}"#)
            .expect("started");
        for id in 0..256 {
            accumulator
                .apply("result", &result_payload(&id.to_string(), "ok", false))
                .expect("report within distinct observer limit");
        }
        accumulator
            .apply("result", &result_payload("0", "tspu_block", false))
            .expect("duplicate at limit does not add a report");
        assert_eq!(accumulator.snapshot().reports.len(), 256);
        let failure = accumulator
            .apply("result", &result_payload("256", "ok", false))
            .expect_err("257th distinct observer is bounded");
        assert_eq!(failure.code, FailureCode::ResponseLimit);
        assert_eq!(accumulator.snapshot().reports.len(), 256);
    }

    #[test]
    fn unsupported_verdicts_never_count_as_ok_and_remain_bounded() {
        let mut accumulator = ProbeAccumulator::new();
        accumulator
            .apply("started", r#"{"online_probes":2}"#)
            .expect("started");
        accumulator
            .apply("result", &result_payload("one", "future_verdict", false))
            .expect("future verdict is retained");
        assert_eq!(accumulator.snapshot().verdict_count("ok"), 0);
        assert_eq!(accumulator.snapshot().verdict_count("future_verdict"), 1);
        match accumulator.apply("result", &result_payload("two", &"x".repeat(65), false)) {
            Ok(_) => assert!(
                accumulator
                    .snapshot()
                    .reports
                    .iter()
                    .flat_map(|report| &report.verdicts)
                    .all(|verdict| verdict.len() <= 64)
            ),
            Err(failure) => assert!(matches!(
                failure.code,
                FailureCode::InvalidResponse | FailureCode::ResponseLimit
            )),
        }
        assert_eq!(accumulator.snapshot().verdict_count("ok"), 0);
    }

    fn probe(verdicts: &[&str]) -> ProbeReport {
        ProbeReport {
            region: Some("fixture region".into()),
            provider: Some("fixture provider".into()),
            asn: Some("AS64500".into()),
            cached: false,
            verdicts: verdicts.iter().map(|value| (*value).to_owned()).collect(),
            target_hop: Some(12),
            dpi_hop: None,
        }
    }

    #[test]
    fn verdict_totals_count_observers_and_keep_future_verdicts_distinct() {
        let result = DynamicResult {
            phase: DynamicPhase::Partial,
            online_probes: Some(4),
            reports: vec![probe(&["tspu"]), probe(&["ok"]), probe(&["future_verdict"])],
        };
        assert_eq!(result.verdict_count("tspu"), 1);
        assert_eq!(result.verdict_count("ok"), 1);
        assert_eq!(result.verdict_count("future_verdict"), 1);
        assert_eq!(result.verdict_count("missing"), 0);
        assert_eq!(result.not_reported(), Some(1));
    }

    #[test]
    fn unknown_observer_total_stays_unknown() {
        let result = DynamicResult {
            phase: DynamicPhase::Partial,
            online_probes: None,
            reports: vec![probe(&["tspu"])],
        };
        assert_eq!(result.not_reported(), None);
    }

    #[test]
    fn base_url_seam_accepts_https_and_http_loopback() {
        for base_url in [
            "https://cheburcheck.ru",
            "https://fixture.example/",
            "http://127.0.0.1:12345",
            "http://[::1]:12345/",
        ] {
            assert!(Client::for_base_url(base_url).is_ok(), "{base_url}");
        }
    }

    #[test]
    fn base_url_seam_rejects_nonloopback_http_and_url_extras() {
        for base_url in [
            "http://192.0.2.1",
            "http://cheburcheck.ru",
            "ftp://127.0.0.1",
            "https://user:secret@cheburcheck.ru",
            "http://user:secret@127.0.0.1",
            "https://cheburcheck.ru/?target=192.0.2.1",
            "https://cheburcheck.ru/#fragment",
            "https://cheburcheck.ru/api",
            "http://127.0.0.1:12345/api",
        ] {
            assert!(Client::for_base_url(base_url).is_err(), "{base_url}");
        }
    }

    fn target() -> IpAddr {
        "192.0.2.42".parse().expect("documentation target")
    }

    fn lookup_body(address: &str, context: &str) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "id": context,
            "target": address,
            "blocked": false,
            "blocked_subnets": [],
            "cdn_providers": {},
            "subscription_url": "https://credential.invalid/private-subscription-token"
        }))
        .expect("lookup fixture JSON")
    }

    fn frame(event_name: &str, data: &str) -> String {
        format!("event: {event_name}\ndata: {data}\n\n")
    }

    fn completed_stream() -> Vec<u8> {
        [
            ": keepalive\n\n".to_owned(),
            frame("unknown_future_event", "this is deliberately not JSON"),
            frame("started", r#"{"online_probes":3}"#),
            frame(
                "result",
                &result_payload("private-observer-one", "tspu_block", false),
            ),
            frame(
                "result",
                &result_payload("private-observer-one", "ok", true),
            ),
            frame(
                "result",
                &result_payload("private-observer-two", "uncertain", true),
            ),
            frame("done", r#"{"response_count":2,"online_probes":3}"#),
        ]
        .concat()
        .into_bytes()
    }

    #[tokio::test]
    async fn static_list_miss_and_dynamic_tspu_remain_independent() {
        let fixture = HttpFixture::scripted(vec![
            (
                "200 OK",
                "Content-Type: application/json\r\n",
                lookup_body("192.0.2.42", "fixture-signed-context"),
            ),
            (
                "200 OK",
                "Content-Type: text/event-stream\r\n",
                completed_stream(),
            ),
        ]);
        let client = Client::for_base_url(&fixture.base_url).expect("loopback client");
        let report = client.check(target()).await;
        assert!(
            !report
                .list
                .as_ref()
                .expect("successful list lookup")
                .blocked
        );
        assert_eq!(report.dynamic.phase, DynamicPhase::Done);
        assert_eq!(report.dynamic.reports.len(), 2);
        assert_eq!(report.dynamic.verdict_count("tspu_block"), 1);
        assert_eq!(report.dynamic.verdict_count("uncertain"), 1);
        assert_eq!(report.dynamic.verdict_count("ok"), 0);
        assert_eq!(report.dynamic.not_reported(), Some(1));
        assert!(report.dynamic.reports.iter().any(|probe| probe.cached));
        assert!(report.failure.is_none());
        let requests = fixture.requests();
        assert_eq!(requests.len(), 2);
        assert!(requests[0].starts_with("GET /api/v1/check?target=192.0.2.42 HTTP/1.1\r\n"));
        assert!(requests[1].starts_with("GET /api/v1/probe/fixture-signed-context HTTP/1.1\r\n"));
        assert!(
            requests
                .iter()
                .all(|request| !request.contains("private-subscription-token"))
        );
        let serialized = serde_json::to_string(&report).expect("serialize public report");
        for private in [
            "fixture-signed-context",
            "private-observer-one",
            "private-observer-two",
            "private-subscription-token",
        ] {
            assert!(
                !serialized.contains(private),
                "private upstream field: {private}"
            );
        }
    }

    #[tokio::test]
    async fn signed_context_is_encoded_as_one_path_segment() {
        let context = "signed/context?x=a&b=%";
        let fixture = HttpFixture::scripted(vec![
            (
                "200 OK",
                "Content-Type: application/json\r\n",
                lookup_body("192.0.2.42", context),
            ),
            (
                "200 OK",
                "Content-Type: text/event-stream\r\n",
                completed_stream(),
            ),
        ]);
        let client = Client::for_base_url(&fixture.base_url).expect("loopback client");
        let report = client.check(target()).await;
        assert_eq!(report.dynamic.phase, DynamicPhase::Done);
        let requests = fixture.requests();
        assert_eq!(requests.len(), 2);
        assert!(
            requests[1]
                .starts_with("GET /api/v1/probe/signed%2Fcontext%3Fx%3Da%26b%3D%25 HTTP/1.1\r\n")
        );
        assert!(
            !serde_json::to_string(&report)
                .expect("serialize report")
                .contains(context)
        );
    }

    #[tokio::test]
    async fn mismatched_lookup_target_never_starts_a_probe() {
        let fixture = HttpFixture::respond(
            "200 OK",
            "Content-Type: application/json\r\n",
            lookup_body("192.0.2.99", "fixture-signed-context"),
        );
        let client = Client::for_base_url(&fixture.base_url).expect("loopback client");
        let report = client.check(target()).await;
        assert_eq!(
            report
                .failure
                .as_ref()
                .expect("target mismatch failure")
                .code,
            FailureCode::InvalidResponse
        );
        assert_eq!(fixture.requests().len(), 1);
        assert_ne!(report.dynamic.phase, DynamicPhase::Done);
    }

    #[tokio::test]
    async fn oversized_signed_context_is_rejected_before_a_probe() {
        let fixture = HttpFixture::respond(
            "200 OK",
            "Content-Type: application/json\r\n",
            lookup_body("192.0.2.42", &"x".repeat(2049)),
        );
        let client = Client::for_base_url(&fixture.base_url).expect("loopback client");
        let report = client.check(target()).await;
        assert_eq!(
            report.failure.as_ref().expect("context bound").code,
            FailureCode::ResponseLimit
        );
        assert_eq!(fixture.requests().len(), 1);
    }

    #[tokio::test]
    async fn early_eof_keeps_partial_reports_and_successful_list_lookup() {
        let partial = [
            frame("started", r#"{"online_probes":2}"#),
            frame(
                "result",
                &result_payload("private-observer", "tspu_block", true),
            ),
        ]
        .concat()
        .into_bytes();
        let fixture = HttpFixture::scripted(vec![
            (
                "200 OK",
                "Content-Type: application/json\r\n",
                lookup_body("192.0.2.42", "fixture-signed-context"),
            ),
            ("200 OK", "Content-Type: text/event-stream\r\n", partial),
        ]);
        let client = Client::for_base_url(&fixture.base_url).expect("loopback client");
        let report = client.check(target()).await;
        assert!(
            !report
                .list
                .as_ref()
                .expect("list result survives stream EOF")
                .blocked
        );
        assert_eq!(report.dynamic.phase, DynamicPhase::Partial);
        assert_eq!(report.dynamic.verdict_count("tspu_block"), 1);
        assert_eq!(report.dynamic.not_reported(), Some(1));
        assert!(report.dynamic.reports[0].cached);
        assert!(report.failure.is_some());
    }

    #[tokio::test]
    async fn malformed_known_stream_event_preserves_prior_reports_as_partial() {
        let partial = [
            frame("started", r#"{"online_probes":2}"#),
            frame(
                "result",
                &result_payload("private-observer", "tspu_block", false),
            ),
            frame("done", "not JSON"),
        ]
        .concat()
        .into_bytes();
        let fixture = HttpFixture::scripted(vec![
            (
                "200 OK",
                "Content-Type: application/json\r\n",
                lookup_body("192.0.2.42", "fixture-signed-context"),
            ),
            ("200 OK", "Content-Type: text/event-stream\r\n", partial),
        ]);
        let client = Client::for_base_url(&fixture.base_url).expect("loopback client");
        let report = client.check(target()).await;
        assert!(report.list.is_some());
        assert_eq!(report.dynamic.phase, DynamicPhase::Partial);
        assert_eq!(report.dynamic.reports.len(), 1);
        assert_eq!(
            report.failure.as_ref().expect("malformed done").code,
            FailureCode::InvalidResponse
        );
    }

    #[tokio::test]
    async fn empty_observer_run_is_unavailable_with_a_list_miss() {
        let empty = [
            frame("started", r#"{"online_probes":0}"#),
            frame("done", r#"{"response_count":0,"online_probes":0}"#),
        ]
        .concat()
        .into_bytes();
        let fixture = HttpFixture::scripted(vec![
            (
                "200 OK",
                "Content-Type: application/json\r\n",
                lookup_body("192.0.2.42", "fixture-signed-context"),
            ),
            ("200 OK", "Content-Type: text/event-stream\r\n", empty),
        ]);
        let client = Client::for_base_url(&fixture.base_url).expect("loopback client");
        let report = client.check(target()).await;
        assert!(!report.list.as_ref().expect("list lookup result").blocked);
        assert_eq!(report.dynamic.phase, DynamicPhase::Unavailable);
        assert_eq!(
            report.failure.as_ref().expect("no observers failure").code,
            FailureCode::NoObservers
        );
        assert!(report.dynamic.reports.is_empty());
    }

    #[tokio::test]
    async fn probe_rate_limit_keeps_list_result_and_does_not_retry() {
        let fixture = HttpFixture::scripted(vec![
            (
                "200 OK",
                "Content-Type: application/json\r\n",
                lookup_body("192.0.2.42", "fixture-signed-context"),
            ),
            ("429 Too Many Requests", "Retry-After: 7\r\n", Vec::new()),
        ]);
        let client = Client::for_base_url(&fixture.base_url).expect("loopback client");
        let report = client.check(target()).await;
        assert!(
            !report
                .list
                .as_ref()
                .expect("list result survives probe failure")
                .blocked
        );
        assert_eq!(report.dynamic.phase, DynamicPhase::Unavailable);
        let failure = report.failure.expect("probe rate limit");
        assert_eq!(failure.code, FailureCode::RateLimited);
        assert_eq!(failure.retry_after_secs, Some(7));
        assert_eq!(fixture.requests().len(), 2);
    }

    #[tokio::test]
    async fn stalled_lookup_times_out_without_starting_a_probe() {
        let fixture = HttpFixture::with_responses(vec![HttpResponse::stall_before_headers()]);
        let client = Client::for_base_url(&fixture.base_url).expect("loopback client");
        let report = tokio::time::timeout(Duration::from_secs(20), client.check(target()))
            .await
            .expect("lookup timeout completes within a bounded wall-clock deadline");
        let failure = report.failure.as_ref().expect("stalled lookup failure");
        assert_eq!(failure.code, FailureCode::Timeout);
        assert_eq!(failure.retry_after_secs, None);
        assert!(report.list.is_none());
        assert_eq!(report.dynamic.phase, DynamicPhase::Unavailable);
        assert!(report.dynamic.reports.is_empty());
        let requests = fixture.requests();
        assert_eq!(
            requests.len(),
            1,
            "timed-out lookup must not retry or probe"
        );
        assert!(requests[0].starts_with("GET /api/v1/check?target=192.0.2.42 HTTP/1.1\r\n"));
    }

    #[tokio::test]
    async fn stalled_probe_times_out_and_keeps_list_and_partial_reports() {
        let partial = [
            frame("started", r#"{"online_probes":2}"#),
            frame(
                "result",
                &result_payload("private-observer", "tspu_block", true),
            ),
        ]
        .concat()
        .into_bytes();
        let fixture = HttpFixture::with_responses(vec![
            HttpResponse::new(
                "200 OK",
                "Content-Type: application/json\r\n",
                lookup_body("192.0.2.42", "fixture-signed-context"),
            ),
            HttpResponse::stream_then_stall("Content-Type: text/event-stream\r\n", partial),
        ]);
        let client = Client::for_base_url(&fixture.base_url).expect("loopback client");
        let report = tokio::time::timeout(Duration::from_secs(75), client.check(target()))
            .await
            .expect("probe timeout completes within a bounded wall-clock deadline");
        let failure = report.failure.as_ref().expect("stalled probe failure");
        assert_eq!(failure.code, FailureCode::Timeout);
        assert_eq!(failure.retry_after_secs, None);
        assert!(
            !report
                .list
                .as_ref()
                .expect("list survives probe timeout")
                .blocked
        );
        assert_eq!(report.dynamic.phase, DynamicPhase::Partial);
        assert_eq!(report.dynamic.reports.len(), 1);
        assert_eq!(report.dynamic.verdict_count("tspu_block"), 1);
        assert_eq!(report.dynamic.verdict_count("ok"), 0);
        assert_eq!(report.dynamic.not_reported(), Some(1));
        assert!(report.dynamic.reports[0].cached);
        let requests = fixture.requests();
        assert_eq!(requests.len(), 2, "timed-out probe must not retry");
        assert!(requests[0].starts_with("GET /api/v1/check?target=192.0.2.42 HTTP/1.1\r\n"));
        assert!(requests[1].starts_with("GET /api/v1/probe/fixture-signed-context HTTP/1.1\r\n"));
        let serialized = serde_json::to_string(&report).expect("serialize partial timeout report");
        assert!(!serialized.contains("fixture-signed-context"));
        assert!(!serialized.contains("private-observer"));
    }

    #[tokio::test]
    async fn lookup_rate_limits_are_bounded_and_never_retried() {
        for (header, expected) in [
            ("", 60),
            ("Retry-After: invalid\r\n", 60),
            ("Retry-After: 0\r\n", 1),
            ("Retry-After: 17\r\n", 17),
            ("Retry-After: 999999\r\n", 3600),
        ] {
            let fixture = HttpFixture::respond("429 Too Many Requests", header, Vec::new());
            let client = Client::for_base_url(&fixture.base_url).expect("loopback client");
            let report = client.check(target()).await;
            let failure = report.failure.expect("429 must be reported");
            assert_eq!(failure.code, FailureCode::RateLimited);
            assert_eq!(failure.retry_after_secs, Some(expected));
            assert!(report.list.is_none());
            assert_ne!(report.dynamic.phase, DynamicPhase::Done);
            let requests = fixture.requests();
            assert_eq!(requests.len(), 1, "429 must not trigger an automatic retry");
            assert!(requests[0].starts_with("GET /api/v1/check?target=192.0.2.42 HTTP/1.1\r\n"));
        }
    }

    #[tokio::test]
    async fn malformed_lookup_is_a_safe_failure_without_a_probe_request() {
        let fixture = HttpFixture::respond(
            "200 OK",
            "Content-Type: application/json\r\n",
            b"not JSON: signed-secret-context".to_vec(),
        );
        let client = Client::for_base_url(&fixture.base_url).expect("loopback client");
        let report = client.check(target()).await;
        assert_eq!(
            report.failure.as_ref().expect("invalid response").code,
            FailureCode::InvalidResponse
        );
        assert!(report.list.is_none());
        assert_eq!(fixture.requests().len(), 1);
        let serialized = serde_json::to_string(&report).expect("serialize safe report");
        assert!(!serialized.contains("signed-secret-context"));
    }

    #[tokio::test]
    async fn lookup_body_over_128_kib_fails_with_response_limit() {
        let fixture = HttpFixture::respond(
            "200 OK",
            "Content-Type: application/json\r\n",
            vec![b' '; 128 * 1024 + 1],
        );
        let client = Client::for_base_url(&fixture.base_url).expect("loopback client");
        let report = client.check(target()).await;
        assert_eq!(
            report.failure.as_ref().expect("oversized response").code,
            FailureCode::ResponseLimit
        );
        assert_eq!(fixture.requests().len(), 1);
        assert_ne!(report.dynamic.phase, DynamicPhase::Done);
    }

    #[tokio::test]
    async fn redirects_are_not_followed() {
        let fixture = HttpFixture::respond(
            "302 Found",
            "Location: /forbidden-redirect?context=signed-secret-context\r\n",
            Vec::new(),
        );
        let client = Client::for_base_url(&fixture.base_url).expect("loopback client");
        let report = client.check(target()).await;
        assert!(report.failure.is_some());
        assert_eq!(fixture.requests().len(), 1);
        assert!(
            !serde_json::to_string(&report)
                .expect("serialize safe report")
                .contains("signed-secret-context")
        );
    }

    #[test]
    fn reports_serialize_only_the_public_report_contract() {
        let report = Report {
            list: Some(ListResult {
                blocked: false,
                blocked_subnets: Vec::new(),
                providers: Vec::new(),
            }),
            dynamic: DynamicResult {
                phase: DynamicPhase::Partial,
                online_probes: Some(2),
                reports: vec![probe(&["tspu"])],
            },
            failure: None,
        };
        let serialized = serde_json::to_value(&report).expect("serialize report");
        let mut keys: Vec<_> = serialized
            .as_object()
            .expect("report object")
            .keys()
            .map(String::as_str)
            .collect();
        keys.sort_unstable();
        assert_eq!(keys, vec!["dynamic", "failure", "list"]);
        assert_eq!(serialized["list"]["blocked"], false);
        assert_eq!(serialized["dynamic"]["reports"][0]["verdicts"][0], "tspu");
    }
}
