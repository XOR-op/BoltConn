use crate::cli::ApproveOptions;
use crate::config::{self, RawInstrumentConfig, default_inbound_ip_addr};
use anyhow::{Context, Result, anyhow, bail};
use boltapi::ProcessParentSchema;
use boltapi::instrument::{InstrumentData, RequestPayload, RequestResponse};
use crossterm::cursor;
use crossterm::event::{Event, EventStream, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use crossterm::execute;
use crossterm::queue;
use crossterm::style::{Print, Stylize};
use crossterm::terminal::{self, Clear, ClearType};
use futures::{SinkExt, StreamExt};
use serde::Deserialize;
use std::collections::HashSet;
use std::fs;
use std::io::{self, Write};
use std::path::PathBuf;
use std::time::Duration;
use tokio::time::{Instant, MissedTickBehavior};
use tokio_tungstenite::connect_async;
use tokio_tungstenite::tungstenite::Message;
use url::Url;

const PANE_HEIGHT: usize = 20;
const FOOTER_HEIGHT: usize = 1;
const UI_HEIGHT: usize = PANE_HEIGHT + FOOTER_HEIGHT;
const RECONNECT_DELAY: Duration = Duration::from_secs(1);
const REFRESH_INTERVAL: Duration = Duration::from_millis(250);

#[derive(Debug, Deserialize)]
struct ApproveConfigFile {
    instrument: Option<RawInstrumentConfig>,
}

#[derive(Debug, Clone)]
struct ApproveConnectionSettings {
    authority: String,
    secret: Option<String>,
}

#[derive(Debug, Clone)]
struct PendingApproval {
    received_at: Instant,
    payload: RequestPayload,
}

impl PendingApproval {
    fn key(&self) -> (u64, u64) {
        (self.payload.sub_id, self.payload.request_id)
    }

    fn remaining_secs(&self, now: Instant) -> u64 {
        self.payload
            .timeout
            .saturating_sub(now.saturating_duration_since(self.received_at).as_secs())
    }

    fn is_expired(&self, now: Instant) -> bool {
        let elapsed = now.saturating_duration_since(self.received_at).as_secs();
        elapsed >= self.payload.timeout
    }
}

#[derive(Debug, Default)]
struct ApproveState {
    queue: Vec<PendingApproval>,
    selected_request: usize,
    detail_scroll: usize,
    connected: bool,
    status: String,
    ignored_messages: u64,
}

impl ApproveState {
    fn set_status(&mut self, status: impl Into<String>) {
        self.status = status.into();
    }

    fn normalize_selection(&mut self) {
        if self.queue.is_empty() {
            self.selected_request = 0;
            self.detail_scroll = 0;
            return;
        }
        if self.selected_request >= self.queue.len() {
            self.selected_request = self.queue.len() - 1;
        }
    }

    fn selected(&self) -> Option<&PendingApproval> {
        self.queue.get(self.selected_request)
    }

    fn enqueue(&mut self, payload: RequestPayload) {
        let key = (payload.sub_id, payload.request_id);
        if let Some(existing) = self.queue.iter_mut().find(|pending| pending.key() == key) {
            existing.payload = payload;
            existing.received_at = Instant::now();
            self.set_status(format!("Refreshed request {} on sub {}", key.1, key.0));
            return;
        }
        self.queue.push(PendingApproval {
            received_at: Instant::now(),
            payload,
        });
        self.selected_request = self.queue.len().saturating_sub(1);
        self.detail_scroll = 0;
        let selected = self.selected().expect("just pushed");
        self.set_status(format!(
            "Queued request {} on sub {}",
            selected.payload.request_id, selected.payload.sub_id
        ));
    }

    fn remove_selected(&mut self) -> Option<PendingApproval> {
        if self.queue.is_empty() {
            return None;
        }
        let removed = self.queue.remove(self.selected_request);
        self.normalize_selection();
        Some(removed)
    }

    fn purge_expired(&mut self, now: Instant) -> usize {
        let before = self.queue.len();
        self.queue.retain(|pending| !pending.is_expired(now));
        let removed = before.saturating_sub(self.queue.len());
        if removed > 0 {
            self.normalize_selection();
        }
        removed
    }

    fn clear_queue(&mut self) -> usize {
        let removed = self.queue.len();
        self.queue.clear();
        self.normalize_selection();
        removed
    }

    fn move_selection_left(&mut self) {
        if self.queue.is_empty() || self.selected_request == 0 {
            return;
        }
        self.selected_request -= 1;
        self.detail_scroll = 0;
    }

    fn move_selection_right(&mut self) {
        if self.queue.is_empty() || self.selected_request + 1 >= self.queue.len() {
            return;
        }
        self.selected_request += 1;
        self.detail_scroll = 0;
    }

    fn scroll_details(&mut self, delta: isize, right_width: usize) {
        let max_scroll = self.max_detail_scroll(right_width);
        if delta < 0 {
            self.detail_scroll = self.detail_scroll.saturating_sub(delta.unsigned_abs());
        } else {
            self.detail_scroll = self
                .detail_scroll
                .saturating_add(delta as usize)
                .min(max_scroll);
        }
    }

    fn max_detail_scroll(&self, right_width: usize) -> usize {
        let visible_lines = PANE_HEIGHT.saturating_sub(1);
        let detail_lines = render_detail_entries(self)
            .into_iter()
            .flat_map(|line| wrap_text(&line, right_width))
            .count();
        detail_lines.saturating_sub(visible_lines)
    }
}

pub(crate) async fn run(opt: ApproveOptions, url_override: Option<String>) -> Result<()> {
    let ids = parse_subscriber_ids(opt.id.as_str())?;
    let ids_label = ids.iter().map(u64::to_string).collect::<Vec<_>>().join(",");
    let connection = resolve_connection_settings(opt.config.as_ref(), url_override, opt.secret)?;
    let subscribe_url = build_subscribe_url(
        connection.authority.as_str(),
        ids.as_slice(),
        connection.secret.as_deref(),
    )?;

    let mut terminal = InlineTerminal::enter()?;
    let mut events = EventStream::new();
    let mut state = ApproveState::default();
    state.set_status(format!(
        "Waiting for ids {} on {}",
        ids_label, connection.authority
    ));
    terminal.draw(&state)?;

    loop {
        state.connected = false;
        state.set_status(format!("Connecting to {}", connection.authority));
        terminal.draw(&state)?;
        match connect_async(subscribe_url.as_str()).await {
            Ok((socket, _)) => {
                state.connected = true;
                state.set_status(format!(
                    "Connected to {} for ids {}",
                    connection.authority, ids_label
                ));
                terminal.draw(&state)?;
                match run_connected_session(socket, &mut state, &mut terminal, &mut events).await? {
                    SessionOutcome::Exit => break,
                    SessionOutcome::Reconnect(reason) => {
                        state.connected = false;
                        let cleared = state.clear_queue();
                        if cleared > 0 {
                            state.set_status(format!(
                                "{}; cleared {} stale request(s)",
                                reason, cleared
                            ));
                        } else {
                            state.set_status(reason);
                        }
                        terminal.draw(&state)?;
                    }
                }
            }
            Err(err) => {
                state.connected = false;
                state.set_status(format!("Connect failed: {}", err));
                terminal.draw(&state)?;
            }
        }
        if wait_for_reconnect_or_exit(&state, &mut terminal, &mut events).await? {
            break;
        }
    }
    Ok(())
}

async fn run_connected_session(
    socket: tokio_tungstenite::WebSocketStream<
        tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
    >,
    state: &mut ApproveState,
    terminal: &mut InlineTerminal,
    events: &mut EventStream,
) -> Result<SessionOutcome> {
    let (mut writer, mut reader) = socket.split();
    let mut tick = tokio::time::interval(REFRESH_INTERVAL);
    tick.set_missed_tick_behavior(MissedTickBehavior::Skip);

    loop {
        terminal.draw(state)?;
        tokio::select! {
            _ = tick.tick() => {
                let expired = state.purge_expired(Instant::now());
                if expired > 0 {
                    state.set_status(format!("Removed {} expired request(s)", expired));
                }
            }
            incoming = reader.next() => {
                match incoming {
                    Some(Ok(Message::Text(text))) => {
                        handle_instrument_text(text.as_ref(), state);
                    }
                    Some(Ok(Message::Close(_))) | None => {
                        return Ok(SessionOutcome::Reconnect("Connection closed".to_string()));
                    }
                    Some(Ok(_)) => {}
                    Some(Err(err)) => {
                        return Ok(SessionOutcome::Reconnect(format!("Connection lost: {}", err)));
                    }
                }
            }
            maybe_event = events.next() => {
                let Some(event) = maybe_event else {
                    return Ok(SessionOutcome::Exit);
                };
                match event? {
                    Event::Key(key) => {
                        match handle_key_event(key, state) {
                            KeyAction::Approve => {
                                if let Some(response) = selected_response(state, "CONTINUE") {
                                    if writer.send(Message::Text(serde_json::to_string(&response)?)).await.is_err() {
                                        return Ok(SessionOutcome::Reconnect("Send failed".to_string()));
                                    }
                                    let approved = state.remove_selected().expect("selected response requires a selection");
                                    state.set_status(format!(
                                        "Approved request {} on sub {}",
                                        approved.payload.request_id, approved.payload.sub_id
                                    ));
                                }
                            }
                            KeyAction::Deny => {
                                if let Some(response) = selected_response(state, "FALLBACK") {
                                    if writer.send(Message::Text(serde_json::to_string(&response)?)).await.is_err() {
                                        return Ok(SessionOutcome::Reconnect("Send failed".to_string()));
                                    }
                                    let denied = state.remove_selected().expect("selected response requires a selection");
                                    state.set_status(format!(
                                        "Denied request {} on sub {}",
                                        denied.payload.request_id, denied.payload.sub_id
                                    ));
                                }
                            }
                            KeyAction::Exit => return Ok(SessionOutcome::Exit),
                            KeyAction::Redraw | KeyAction::None => {}
                        }
                    }
                    Event::Resize(_, _) => {}
                    _ => {}
                }
            }
        }
    }
}

async fn wait_for_reconnect_or_exit(
    state: &ApproveState,
    terminal: &mut InlineTerminal,
    events: &mut EventStream,
) -> Result<bool> {
    let delay = tokio::time::sleep(RECONNECT_DELAY);
    tokio::pin!(delay);
    loop {
        tokio::select! {
            _ = &mut delay => return Ok(false),
            maybe_event = events.next() => {
                let Some(event) = maybe_event else {
                    return Ok(true);
                };
                match event? {
                    Event::Key(key)
                        if is_exit_key(&key) => {
                            return Ok(true);
                        }
                    Event::Resize(_, _) => {
                        terminal.draw(state)?;
                    }
                    _ => {}
                }
            }
        }
    }
}

fn handle_instrument_text(encoded: &str, state: &mut ApproveState) {
    let Some(frame) = InstrumentData::decode_string(encoded) else {
        state.ignored_messages = state.ignored_messages.saturating_add(1);
        state.set_status("Ignored malformed instrument frame");
        return;
    };

    match serde_json::from_str::<RequestPayload>(frame.message.as_str()) {
        Ok(payload) => {
            if payload.timeout == 0 {
                state.set_status(format!(
                    "Ignored request {} on sub {} with zero timeout",
                    payload.request_id, payload.sub_id
                ));
                return;
            }
            state.enqueue(payload);
        }
        Err(_) => {
            state.ignored_messages = state.ignored_messages.saturating_add(1);
            state.set_status(format!("Ignored non-request message on sub {}", frame.id));
        }
    }
}

fn selected_response(state: &ApproveState, route: &str) -> Option<RequestResponse> {
    let selected = state.selected()?;
    Some(RequestResponse {
        sub_id: selected.payload.sub_id,
        request_id: selected.payload.request_id,
        route: route.to_string(),
    })
}

fn resolve_connection_settings(
    config_override: Option<&PathBuf>,
    url_override: Option<String>,
    secret_override: Option<String>,
) -> Result<ApproveConnectionSettings> {
    if url_override.is_some() || secret_override.is_some() {
        let authority = url_override.ok_or_else(|| {
            anyhow!(
                "`boltconn approve`: --url <host:port> is required when override flags are used"
            )
        })?;
        return Ok(ApproveConnectionSettings {
            authority: normalize_authority(authority.as_str())?,
            secret: secret_override,
        });
    }

    load_connection_settings_from_config(config_override)
}

fn load_connection_settings_from_config(
    config_override: Option<&PathBuf>,
) -> Result<ApproveConnectionSettings> {
    let (config_path, _, _) = config::parse_paths(&config_override.cloned(), &None, &None)
        .context("Failed to resolve config path")?;
    let config_file_path = config_path.join("config.yml");
    let config_text = fs::read_to_string(&config_file_path)
        .with_context(|| format!("Failed to read {}", config_file_path.to_string_lossy()))?;
    let config_file: ApproveConfigFile = serde_yaml::from_str(config_text.as_str())
        .with_context(|| format!("Failed to parse {}", config_file_path.to_string_lossy()))?;
    let instrument = config_file.instrument.ok_or_else(|| {
        anyhow!(
            "`instrument` is not configured in {}",
            config_file_path.to_string_lossy()
        )
    })?;
    Ok(ApproveConnectionSettings {
        authority: instrument
            .api_addr
            .as_socket_addr(default_inbound_ip_addr)
            .to_string(),
        secret: instrument.secret,
    })
}

fn parse_subscriber_ids(raw: &str) -> Result<Vec<u64>> {
    let mut seen = HashSet::new();
    let mut ids = Vec::new();
    for part in raw.split(',') {
        let trimmed = part.trim();
        if trimmed.is_empty() {
            bail!("`boltconn approve`: empty subscriber id in `{}`", raw);
        }
        let id = trimmed
            .parse::<u64>()
            .with_context(|| format!("`boltconn approve`: invalid subscriber id `{}`", trimmed))?;
        if seen.insert(id) {
            ids.push(id);
        }
    }
    if ids.is_empty() {
        bail!("`boltconn approve`: at least one subscriber id is required");
    }
    Ok(ids)
}

fn normalize_authority(authority: &str) -> Result<String> {
    let authority = authority.trim();
    if authority.is_empty()
        || authority.contains("://")
        || authority.contains('/')
        || authority.contains('?')
        || authority.contains('#')
    {
        bail!("`boltconn approve`: --url must be a bare host:port value");
    }
    Url::parse(format!("ws://{authority}/subscribe").as_str()).with_context(|| {
        format!(
            "`boltconn approve`: invalid --url authority `{}`",
            authority
        )
    })?;
    Ok(authority.to_string())
}

fn build_subscribe_url(authority: &str, ids: &[u64], secret: Option<&str>) -> Result<Url> {
    let mut url = Url::parse(format!("ws://{authority}/subscribe").as_str())
        .with_context(|| format!("Failed to build subscribe URL for `{}`", authority))?;
    url.query_pairs_mut().append_pair(
        "id",
        ids.iter()
            .map(u64::to_string)
            .collect::<Vec<_>>()
            .join(",")
            .as_str(),
    );
    if let Some(secret) = secret {
        url.query_pairs_mut().append_pair("secret", secret);
    }
    Ok(url)
}

enum SessionOutcome {
    Exit,
    Reconnect(String),
}

enum KeyAction {
    None,
    Redraw,
    Approve,
    Deny,
    Exit,
}

fn handle_key_event(key: KeyEvent, state: &mut ApproveState) -> KeyAction {
    if matches!(key.kind, KeyEventKind::Release) {
        return KeyAction::None;
    }
    if is_exit_key(&key) {
        return KeyAction::Exit;
    }

    let (_, right_width) = split_widths(current_terminal_width());
    match key.code {
        KeyCode::Left => {
            state.move_selection_left();
            KeyAction::Redraw
        }
        KeyCode::Right => {
            state.move_selection_right();
            KeyAction::Redraw
        }
        KeyCode::Up => {
            state.scroll_details(-1, right_width);
            KeyAction::Redraw
        }
        KeyCode::Down => {
            state.scroll_details(1, right_width);
            KeyAction::Redraw
        }
        KeyCode::Enter | KeyCode::Char('a') => KeyAction::Approve,
        KeyCode::Char('x') => KeyAction::Deny,
        _ => KeyAction::None,
    }
}

fn is_exit_key(key: &KeyEvent) -> bool {
    key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c')
}

struct InlineTerminal {
    stdout: io::Stdout,
    drawn_once: bool,
}

impl InlineTerminal {
    fn enter() -> io::Result<Self> {
        terminal::enable_raw_mode()?;
        let mut stdout = io::stdout();
        execute!(stdout, cursor::Hide)?;
        Ok(Self {
            stdout,
            drawn_once: false,
        })
    }

    fn draw(&mut self, state: &ApproveState) -> io::Result<()> {
        let lines = render_ui(state, current_terminal_width());
        if self.drawn_once {
            queue!(self.stdout, cursor::MoveUp(UI_HEIGHT as u16))?;
        }
        for line in lines {
            queue!(
                self.stdout,
                cursor::MoveToColumn(0),
                Clear(ClearType::CurrentLine),
                Print(line),
                Print("\r\n")
            )?;
        }
        self.stdout.flush()?;
        self.drawn_once = true;
        Ok(())
    }
}

impl Drop for InlineTerminal {
    fn drop(&mut self) {
        let _ = execute!(self.stdout, cursor::Show);
        let _ = terminal::disable_raw_mode();
        let _ = self.stdout.flush();
    }
}

fn render_ui(state: &ApproveState, total_width: usize) -> Vec<String> {
    let (left_width, right_width) = split_widths(total_width);
    let now = Instant::now();
    let left_lines = render_boxed_pane(
        render_queue_title(state),
        render_queue_lines(state, left_width.saturating_sub(2), now),
        left_width,
    );
    let right_lines = render_boxed_pane(
        render_detail_title(state, now),
        render_detail_lines(state, right_width.saturating_sub(2), now),
        right_width,
    );
    let mut rows = Vec::with_capacity(UI_HEIGHT);
    for row in 0..PANE_HEIGHT {
        rows.push(format!("{} {}", left_lines[row], right_lines[row]));
    }
    rows.push(centered_bold_fill_text(
        render_footer(state).as_str(),
        total_width,
        '─',
    ));
    rows
}

fn render_boxed_pane(title: String, body_lines: Vec<String>, width: usize) -> Vec<String> {
    let inner_width = width.saturating_sub(2);
    let body_height = PANE_HEIGHT.saturating_sub(2);
    let mut lines = Vec::with_capacity(PANE_HEIGHT);
    lines.push(format!(
        "┌{}┐",
        centered_bold_border_title(&title, inner_width)
    ));
    for line in body_lines.into_iter().take(body_height) {
        lines.push(format!("│{}│", fit_text(&line, inner_width)));
    }
    while lines.len() < PANE_HEIGHT.saturating_sub(1) {
        lines.push(format!("│{}│", " ".repeat(inner_width)));
    }
    lines.push(format!("└{}┘", "─".repeat(inner_width)));
    lines
}

fn render_queue_title(state: &ApproveState) -> String {
    format!("Queue ({})", state.queue.len())
}

fn render_queue_lines(state: &ApproveState, width: usize, now: Instant) -> Vec<String> {
    let mut lines = Vec::with_capacity(PANE_HEIGHT.saturating_sub(2));
    let body_height = PANE_HEIGHT.saturating_sub(2);
    if state.queue.is_empty() {
        while lines.len() < body_height {
            lines.push(String::new());
        }
        return lines;
    }

    let visible_rows = body_height.min(state.queue.len());
    let mut start = state.selected_request.saturating_sub(visible_rows / 2);
    let max_start = state.queue.len().saturating_sub(visible_rows);
    if start > max_start {
        start = max_start;
    }
    for (offset, pending) in state
        .queue
        .iter()
        .skip(start)
        .take(visible_rows)
        .enumerate()
    {
        let index = start + offset;
        let marker = if index == state.selected_request {
            ">"
        } else {
            " "
        };
        let process = pending.payload.process_name.as_deref().unwrap_or("-");
        let summary = format!(
            "{} [{}] {:>3}s #{} {} -> {}",
            marker,
            pending.payload.sub_id,
            pending.remaining_secs(now),
            pending.payload.request_id,
            process,
            pending.payload.addr_dst
        );
        lines.push(summary);
    }
    while lines.len() < body_height {
        lines.push(String::new());
    }
    if width == 0 {
        return vec![String::new(); body_height];
    }
    lines
}

fn render_detail_title(state: &ApproveState, now: Instant) -> String {
    match state.selected() {
        Some(selected) => format!(
            "Details #{} [{}] {:>3}s",
            selected.payload.request_id,
            selected.payload.sub_id,
            selected.remaining_secs(now)
        ),
        None => "Details".to_string(),
    }
}

fn render_detail_lines(state: &ApproveState, width: usize, _now: Instant) -> Vec<String> {
    let mut wrapped = Vec::new();
    for line in render_detail_entries(state) {
        wrapped.extend(wrap_text(&line, width));
    }

    let mut lines = Vec::with_capacity(PANE_HEIGHT.saturating_sub(2));
    let body_height = PANE_HEIGHT.saturating_sub(2);
    let start = state
        .detail_scroll
        .min(wrapped.len().saturating_sub(body_height));
    for line in wrapped.into_iter().skip(start).take(body_height) {
        lines.push(line);
    }
    while lines.len() < body_height {
        lines.push(String::new());
    }
    lines
}

fn render_detail_entries(state: &ApproveState) -> Vec<String> {
    let Some(selected) = state.selected() else {
        return Vec::new();
    };
    let payload = &selected.payload;
    let mut lines = vec![
        format!(
            "[{}] #{} {}? [{}/{}s]",
            payload.time_hms_ms,
            payload.sub_id,
            payload.suggested_route,
            selected.remaining_secs(Instant::now()),
            payload.timeout,
        ),
        format!(
            "{}->{} ({}, {}{})",
            payload
                .ip_local
                .as_deref()
                .unwrap_or(payload.addr_src.as_str()),
            payload.addr_dst,
            payload.conn_type,
            payload.inbound_type,
            payload.inbound_port.map_or_else(
                || "".to_string(),
                |port| format!(
                    ":{port}{}",
                    payload
                        .inbound_user
                        .as_ref()
                        .map_or_else(|| "".to_string(), |user| format!("@{user}"))
                )
            )
        ),
        format!(
            "({}) {} {}",
            payload
                .process_pid
                .map(|pid| pid.to_string())
                .unwrap_or_else(|| "N/A".to_string()),
            payload.process_name.as_deref().unwrap_or("N/A"),
            payload
                .process_tag
                .as_deref()
                .map_or_else(|| "".to_string(), |tag| format!("#{}", tag)),
        ),
        format!("  path: {}", payload.process_path.as_deref().unwrap_or(""),),
        format!(
            "  cmd:  {}",
            payload.process_cmdline.as_deref().unwrap_or(""),
        ),
        format!("  cwd:  {}", payload.process_cwd.as_deref().unwrap_or(""),),
    ];

    if payload.process_parent_all.is_empty() {
        lines.push("  none".to_string());
    } else {
        for parent in payload.process_parent_all.iter() {
            lines.extend(render_parent_entry(parent));
        }
    }
    lines
}

fn render_parent_entry(parent: &ProcessParentSchema) -> Vec<String> {
    vec![
        format!(
            "|-({}) {}",
            parent.pid,
            parent.name.as_deref().unwrap_or("N/A")
        ),
        format!("|   path: {}", parent.path.as_deref().unwrap_or("")),
        format!("|   cmd:  {}", parent.cmdline.as_deref().unwrap_or("")),
        format!("|   cwd:  {}", parent.cwd.as_deref().unwrap_or("")),
    ]
}

fn render_footer(state: &ApproveState) -> String {
    format!(
        "{} {}",
        if state.connected {
            "CONNECTED"
        } else {
            "DISCONNECTED"
        },
        state.status
    )
}

fn split_widths(total_width: usize) -> (usize, usize) {
    let total_width = total_width.max(5);
    let available = total_width - 1;
    let left = (available * 2 / 5).clamp(2, available.saturating_sub(2));
    let right = available - left;
    (left, right)
}

fn current_terminal_width() -> usize {
    terminal::size()
        .map(|(width, _)| width as usize)
        .unwrap_or(80)
}

fn fit_text(text: &str, width: usize) -> String {
    if width == 0 {
        return String::new();
    }
    let trimmed = truncate_text(text, width);
    let len = trimmed.chars().count();
    if len >= width {
        trimmed
    } else {
        format!("{}{}", trimmed, " ".repeat(width - len))
    }
}

fn centered_bold_fill_text(text: &str, width: usize, fill: char) -> String {
    if width == 0 {
        return String::new();
    }
    let decorated = if width >= 3 {
        format!(" {} ", truncate_text(text, width.saturating_sub(2)))
    } else {
        truncate_text(text, width)
    };
    let len = decorated.chars().count();
    let left_pad = width.saturating_sub(len) / 2;
    let right_pad = width.saturating_sub(len + left_pad);
    format!(
        "{}{}{}",
        fill.to_string().repeat(left_pad),
        decorated.bold(),
        fill.to_string().repeat(right_pad)
    )
}

fn centered_bold_border_title(text: &str, width: usize) -> String {
    if width == 0 {
        return String::new();
    }

    let decorated = if width >= 3 {
        format!(" {} ", truncate_text(text, width.saturating_sub(2)))
    } else {
        truncate_text(text, width)
    };
    let len = decorated.chars().count();
    let left_pad = width.saturating_sub(len) / 2;
    let right_pad = width.saturating_sub(len + left_pad);
    format!(
        "{}{}{}",
        "─".repeat(left_pad),
        decorated.bold(),
        "─".repeat(right_pad)
    )
}

fn truncate_text(text: &str, width: usize) -> String {
    let chars: Vec<char> = text.chars().collect();
    if chars.len() <= width {
        return text.to_string();
    }
    if width <= 3 {
        return chars.into_iter().take(width).collect();
    }
    chars
        .into_iter()
        .take(width - 3)
        .chain("...".chars())
        .collect()
}

fn wrap_text(text: &str, width: usize) -> Vec<String> {
    if width == 0 {
        return vec![String::new()];
    }
    if text.is_empty() {
        return vec![String::new()];
    }

    let mut wrapped = Vec::new();
    let mut current = String::new();
    for ch in text.chars() {
        current.push(ch);
        if current.chars().count() == width {
            wrapped.push(current);
            current = String::new();
        }
    }
    if !current.is_empty() {
        wrapped.push(current);
    }
    wrapped
}

#[cfg(test)]
mod tests {
    use super::{
        ApproveState, PANE_HEIGHT, UI_HEIGHT, build_subscribe_url, parse_subscriber_ids, render_ui,
        resolve_connection_settings,
    };
    use boltapi::instrument::RequestPayload;
    use std::time::Duration;
    use tokio::time::Instant;

    fn sample_payload(request_id: u64, timeout: u64) -> RequestPayload {
        RequestPayload {
            sub_id: 31,
            request_id,
            suggested_route: "CONTINUE".to_string(),
            timeout,
            addr_src: "127.0.0.1:50000".to_string(),
            addr_dst: "example.com:443".to_string(),
            addr_resolved_dst: Some("93.184.216.34:443".to_string()),
            ip_local: Some("192.168.1.10".to_string()),
            inbound_type: "tun".to_string(),
            inbound_port: None,
            inbound_user: None,
            conn_type: "tcp".to_string(),
            process_name: Some("curl".to_string()),
            process_cmdline: Some("curl https://example.com".to_string()),
            process_path: Some("/usr/bin/curl".to_string()),
            process_cwd: Some("/tmp".to_string()),
            process_pid: Some(1234),
            process_tag: None,
            process_parent_all: Vec::new(),
            time_hms_ms: "10:00:00.000".to_string(),
        }
    }

    #[test]
    fn test_parse_subscriber_ids_deduplicates_and_preserves_order() {
        let ids = parse_subscriber_ids("31, 32,31,100").unwrap();
        assert_eq!(ids, vec![31, 32, 100]);
    }

    #[test]
    fn test_build_subscribe_url_includes_secret() {
        let url = build_subscribe_url("127.0.0.1:9001", &[31, 32], Some("secret")).unwrap();
        assert_eq!(
            url.as_str(),
            "ws://127.0.0.1:9001/subscribe?id=31%2C32&secret=secret"
        );
    }

    #[test]
    fn test_override_requires_url() {
        let err = resolve_connection_settings(None, None, Some("secret".to_string())).unwrap_err();
        assert!(err.to_string().contains("--url <host:port> is required"));
    }

    #[test]
    fn test_purge_expired_requests_adjusts_selection() {
        let mut state = ApproveState::default();
        state.enqueue(sample_payload(41, 30));
        state.enqueue(sample_payload(42, 30));
        state.selected_request = 1;
        state.queue[0].received_at = Instant::now() - Duration::from_secs(31);
        state.queue[1].received_at = Instant::now() - Duration::from_secs(31);

        let removed = state.purge_expired(Instant::now());
        assert_eq!(removed, 2);
        assert!(state.queue.is_empty());
        assert_eq!(state.selected_request, 0);
    }

    #[test]
    fn test_render_ui_has_fixed_height() {
        let mut state = ApproveState::default();
        state.enqueue(sample_payload(42, 30));
        let lines = render_ui(&state, 80);
        assert_eq!(lines.len(), 21);
    }

    #[test]
    fn test_render_ui_draws_thin_line_borders_for_panes() {
        let mut state = ApproveState::default();
        state.enqueue(sample_payload(42, 30));
        let lines = render_ui(&state, 80);

        assert!(lines[0].contains('┌'));
        assert!(lines[0].contains('┐'));
        assert!(lines[0].contains('─'));
        assert!(!lines[0].contains("48;2;52;58;64"));
        assert!(lines[1].starts_with('│'));
        assert!(lines[1].contains("│ │"));
        assert!(lines[PANE_HEIGHT - 1].contains('└'));
        assert!(lines[PANE_HEIGHT - 1].contains('┘'));
        assert!(!lines[UI_HEIGHT - 1].contains('┌'));
        assert!(lines[UI_HEIGHT - 1].contains('─'));
    }
}
