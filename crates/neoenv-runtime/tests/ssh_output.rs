//! Observable streaming contracts through the public writer boundary.
use neoenv_runtime::ssh_output::{
    GroupedOutput,
    OutputChannel::{Stderr, Stdout},
};
use std::{
    cell::RefCell,
    io::{self, Write},
    rc::Rc,
    time::{Duration, Instant},
};

#[derive(Clone, Default)]
struct Recorder(Rc<RefCell<Vec<u8>>>);
impl Write for Recorder {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0.borrow_mut().extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
impl Recorder {
    fn text(&self) -> String {
        String::from_utf8_lossy(&self.0.borrow()).into_owned()
    }
}

#[test]
fn alternating_hosts_and_streams_flush_groups_not_each_incoming_line() {
    let output = Recorder::default();
    let error = Recorder::default();
    let mut first = GroupedOutput::new("alpha", &[], output.clone(), error.clone(), false).unwrap();
    let mut second = GroupedOutput::new("beta", &[], output.clone(), error.clone(), false).unwrap();
    let now = Instant::now();
    first.push(Stdout, b"one\n", now).unwrap();
    second.push(Stdout, b"two\n", now).unwrap();
    first.push(Stdout, b"three\n", now).unwrap();
    second.push(Stderr, b"warning", now).unwrap();
    assert!(output.text().is_empty());
    first.tick(now + Duration::from_millis(100)).unwrap();
    second.tick(now + Duration::from_millis(100)).unwrap();
    let text = output.text();
    assert!(text.find("one").unwrap() < text.find("three").unwrap());
    assert!(text.find("three").unwrap() < text.find("two").unwrap());
    assert!(text.contains("[alpha stdout] one\n"));
    assert!(text.contains("[alpha stdout] three\n"));
    assert!(text.contains("[beta stdout] two\n"));
    assert!(error.text().contains("[beta stderr] warning"));
    assert!(text.contains("\x1b[0m"));
    first.finish().unwrap();
    second.finish().unwrap();
}

#[test]
fn secret_prefixes_are_redacted_at_latency_deadline_and_remainders_cannot_leak() {
    let output = Recorder::default();
    let mut groups = GroupedOutput::new(
        "alpha",
        &["fixture-password".into()],
        output.clone(),
        Recorder::default(),
        false,
    )
    .unwrap();
    let now = Instant::now();
    groups.push(Stdout, b"before fi", now).unwrap();
    groups.tick(now + Duration::from_millis(101)).unwrap();
    assert!(output.text().contains("before [REDACTED]"));
    groups
        .push(
            Stdout,
            b"\x1b[31mxture-pass",
            now + Duration::from_millis(102),
        )
        .unwrap();
    groups
        .push(
            Stdout,
            b"\x1b[0mword after",
            now + Duration::from_millis(103),
        )
        .unwrap();
    groups.finish().unwrap();
    let text = output.text();
    assert!(!text.contains("fixture"));
    assert!(!text.contains("password"));
    assert!(!text.contains("xture-pass"));
    assert!(text.contains("after"));
}

#[test]
fn ansi_is_bounded_and_colour_resets_separate_hosts_and_partial_groups() {
    let output = Recorder::default();
    let mut first =
        GroupedOutput::new("alpha", &[], output.clone(), Recorder::default(), false).unwrap();
    let now = Instant::now();
    first.push(Stdout, b"\x1b[3", now).unwrap();
    first
        .push(Stdout, b"1mred\nstill-red\x1b]52;c;never-show\x07", now)
        .unwrap();
    first.push(Stdout, b"\x1b[2Jvisible\x1b[", now).unwrap();
    first.finish().unwrap();
    assert!(output.text().ends_with("\x1b[0m\n"));
    let mut second =
        GroupedOutput::new("beta", &[], output.clone(), Recorder::default(), false).unwrap();
    second.push(Stdout, b"plain", now).unwrap();
    second.finish().unwrap();
    let text = output.text();
    assert!(text.contains("\x1b[31mred"));
    assert!(!text.contains("never-show"));
    assert!(!text.contains("\x1b[2J"));
    assert!(text.contains("\x1b[0m[beta stdout] plain"));
    assert!(!text.ends_with("\x1b["));
}

#[derive(Clone, Default)]
struct Counter(Rc<RefCell<(usize, usize, usize)>>);
impl Write for Counter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let mut stats = self.0.borrow_mut();
        stats.0 += bytes.len();
        stats.1 = stats.1.max(bytes.len());
        stats.2 += 1;
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[test]
fn huge_no_newline_input_streams_before_eof_with_bounded_write_frames() {
    let output = Counter::default();
    let mut groups =
        GroupedOutput::new("alpha", &[], output.clone(), Counter::default(), false).unwrap();
    let payload = vec![b'x'; 2 * 1024 * 1024];
    groups.push(Stdout, &payload, Instant::now()).unwrap();
    assert!(output.0.borrow().0 >= payload.len() - 4096);
    groups.finish().unwrap();
    let stats = output.0.borrow();
    assert!(stats.1 <= 8192);
    assert!(stats.2 >= payload.len() / 8192);
}

#[test]
fn json_mode_keeps_stdout_clean_and_finalization_flushes_partial_error_and_cancel_tails() {
    let output = Recorder::default();
    let error = Recorder::default();
    let mut groups = GroupedOutput::new(
        "alpha\ninjected",
        &["private".into()],
        output.clone(),
        error.clone(),
        true,
    )
    .unwrap();
    let now = Instant::now();
    groups.push(Stdout, b"private", now).unwrap();
    groups.push(Stderr, b"partial pri", now).unwrap();
    // finish is shared by EOF, failure and cancellation, and conservatively
    // censors the ambiguous final prefix rather than leaking it.
    groups.finish().unwrap();
    assert!(output.text().is_empty());
    assert!(error.text().contains("alpha\\x0ainjected"));
    assert!(error.text().contains("[REDACTED]"));
    assert!(!error.text().contains("private"));
    assert!(!error.text().contains("partial pri"));
}

struct Broken;
impl Write for Broken {
    fn write(&mut self, _: &[u8]) -> io::Result<usize> {
        Err(io::Error::other("not-rendered-private-cause"))
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[test]
fn failed_writer_still_flushes_the_other_stream_without_echoing_causes() {
    let error = Recorder::default();
    let mut groups = GroupedOutput::new("alpha", &[], Broken, error.clone(), false).unwrap();
    groups.push(Stderr, b"error-tail", Instant::now()).unwrap();
    let message = groups
        .push(Stdout, &vec![b'x'; 8192], Instant::now())
        .unwrap_err();
    assert_eq!(message, "SSH console output failed");
    let _ = groups.finish();
    assert!(error.text().contains("error-tail"));
}

#[test]
fn redaction_and_alias_resource_limits_fail_before_output() {
    assert!(
        GroupedOutput::new(
            "alpha",
            &["x".repeat(257)],
            Recorder::default(),
            Recorder::default(),
            false
        )
        .is_err()
    );
    assert!(
        GroupedOutput::new(
            "alpha",
            &["secret\nline".into()],
            Recorder::default(),
            Recorder::default(),
            false
        )
        .is_err()
    );
    assert!(
        GroupedOutput::new(
            &"a".repeat(129),
            &[],
            Recorder::default(),
            Recorder::default(),
            false
        )
        .is_err()
    );
}

#[test]
fn unicode_group_boundaries_remain_valid_and_c1_controls_cannot_bypass_sanitization() {
    let output = Recorder::default();
    let mut groups =
        GroupedOutput::new("alpha", &[], output.clone(), Recorder::default(), false).unwrap();
    let payload = format!("{}λ界\u{009b}2Jdone", "x".repeat(4095));
    groups
        .push(Stdout, payload.as_bytes(), Instant::now())
        .unwrap();
    groups.finish().unwrap();
    let bytes = output.0.borrow();
    let text = std::str::from_utf8(&bytes).unwrap();
    assert!(text.contains('λ'));
    assert!(text.contains('界'));
    assert!(!text.contains('\u{009b}'));
    assert!(text.contains("2Jdone"));
}

#[test]
fn truecolour_zero_components_do_not_erase_bold_style_replay() {
    let output = Recorder::default();
    let mut groups =
        GroupedOutput::new("alpha", &[], output.clone(), Recorder::default(), false).unwrap();
    let mut payload = b"\x1b[1m\x1b[38;2;255;0;0m".to_vec();
    payload.extend_from_slice(&vec![b'x'; 8192]);
    groups.push(Stdout, &payload, Instant::now()).unwrap();
    groups.finish().unwrap();
    assert!(output.text().matches("\x1b[1m").count() >= 2);
}

#[test]
fn simultaneously_due_streams_alternate_priority_in_json_mode() {
    let output = Recorder::default();
    let mut groups =
        GroupedOutput::new("alpha", &[], Recorder::default(), output.clone(), true).unwrap();
    let now = Instant::now();
    groups.push(Stdout, b"O1", now).unwrap();
    groups.push(Stderr, b"E1", now).unwrap();
    groups.tick(now + Duration::from_millis(100)).unwrap();
    groups
        .push(Stdout, b"O2", now + Duration::from_millis(200))
        .unwrap();
    groups
        .push(Stderr, b"E2", now + Duration::from_millis(200))
        .unwrap();
    groups.tick(now + Duration::from_millis(300)).unwrap();
    groups.finish().unwrap();
    let text = output.text();
    assert!(text.find("E1").unwrap() < text.find("O1").unwrap());
    assert!(text.find("O2").unwrap() < text.find("E2").unwrap());
}
