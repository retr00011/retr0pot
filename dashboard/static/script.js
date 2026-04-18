/* ═══════════════════════════════════════════════════════
   retr0pot Dashboard — Live Client Script
   by retr0
   ═══════════════════════════════════════════════════════ */

const POLL_INTERVAL = 3000; // 3 seconds
let lastEventCount = 0;
let lastUpdate = Date.now();
let feedCleared = false;

// ─── Helpers ─────────────────────────────────────────────
function timeAgo(isoString) {
    const d = new Date(isoString);
    const now = new Date();
    const diff = Math.floor((now - d) / 1000);
    if (diff < 5) return "just now";
    if (diff < 60) return `${diff}s ago`;
    if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
    if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
    return `${Math.floor(diff / 86400)}d ago`;
}

function extractTime(isoString) {
    try {
        return new Date(isoString).toLocaleTimeString('en-US', {
            hour12: false,
            hour: '2-digit',
            minute: '2-digit',
            second: '2-digit'
        });
    } catch {
        return "??:??:??";
    }
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

function truncate(str, maxLen = 60) {
    if (!str) return '';
    return str.length > maxLen ? str.substring(0, maxLen) + '…' : str;
}

// ─── Feed Rendering ──────────────────────────────────────
function renderFeedEvent(event) {
    const time = extractTime(event.timestamp);
    const type = event.type || 'unknown';
    const service = event.service || '?';
    const ip = `${event.src_ip}:${event.src_port}`;

    let dataStr = '';
    const data = event.data || {};

    if (type === 'auth_attempt') {
        if (data.username && data.password) {
            dataStr = `${data.username} / ${data.password}`;
        } else if (data.post_body) {
            dataStr = truncate(data.post_body, 50);
        } else if (data.raw_data) {
            dataStr = truncate(data.raw_data, 50);
        }
    } else if (type === 'command') {
        dataStr = data.command || '';
    } else if (type === 'scan') {
        dataStr = `${data.method || '?'} ${data.path || '/'}`;
    } else if (type === 'payload') {
        dataStr = truncate(data.command || 'payload detected', 50);
    }

    return `
        <div class="feed-event type-${type}">
            <span class="feed-time">${time}</span>
            <span class="feed-type ${type}">${type.toUpperCase()}</span>
            <span class="feed-service">${service}</span>
            <span class="feed-ip">${escapeHtml(ip)}</span>
            <span class="feed-data">${escapeHtml(dataStr)}</span>
        </div>
    `;
}

// ─── Stats Update ────────────────────────────────────────
function updateStats(stats) {
    // Animate number changes
    animateValue('totalEvents', stats.total_events || 0);
    animateValue('uniqueIps', stats.total_unique_ips || 0);
    animateValue('totalCreds', (stats.credentials || []).length);
    animateValue('totalCmds', (stats.commands || []).length);

    // Service chart
    updateServiceChart(stats.by_service || {});

    // Top attackers
    updateTopAttackers(stats.top_ips || {});

    // Credentials table
    updateCredsTable(stats.credentials || []);

    // Commands table
    updateCmdsTable(stats.commands || []);
}

function animateValue(elementId, newValue) {
    const el = document.getElementById(elementId);
    if (!el) return;
    const current = parseInt(el.textContent) || 0;
    if (current === newValue) return;

    // Flash the parent card
    const card = el.closest('.stat-card');
    if (card && newValue > current) {
        card.classList.add('flash');
        setTimeout(() => card.classList.remove('flash'), 500);
    }

    // Counter animation
    const diff = newValue - current;
    const steps = Math.min(Math.abs(diff), 20);
    const stepValue = diff / steps;
    let step = 0;

    const timer = setInterval(() => {
        step++;
        if (step >= steps) {
            el.textContent = newValue.toLocaleString();
            clearInterval(timer);
        } else {
            el.textContent = Math.round(current + stepValue * step).toLocaleString();
        }
    }, 30);
}

// ─── Service Chart ───────────────────────────────────────
function updateServiceChart(byService) {
    const container = document.getElementById('serviceChart');
    const total = Object.values(byService).reduce((a, b) => a + b, 0);
    if (total === 0) {
        container.innerHTML = '<div class="feed-empty">No data yet</div>';
        return;
    }

    const services = ['SSH', 'HTTP', 'FTP', 'Telnet'];
    const colors = { 'SSH': 'ssh', 'HTTP': 'http', 'FTP': 'ftp', 'Telnet': 'telnet' };

    let html = '<div class="bar-chart">';
    for (const svc of services) {
        const count = byService[svc] || 0;
        const pct = total > 0 ? (count / total * 100) : 0;
        html += `
            <div class="bar-row">
                <span class="bar-label">${svc}</span>
                <div class="bar-track">
                    <div class="bar-fill ${colors[svc]}" style="width: ${pct}%"></div>
                </div>
                <span class="bar-count">${count}</span>
            </div>
        `;
    }
    html += '</div>';
    container.innerHTML = html;
}

// ─── Top Attackers ───────────────────────────────────────
function updateTopAttackers(topIps) {
    const container = document.getElementById('topAttackers');
    const entries = Object.entries(topIps);
    if (entries.length === 0) {
        container.innerHTML = '<div class="feed-empty">No attackers yet</div>';
        return;
    }

    let html = '';
    entries.forEach(([ip, count], i) => {
        html += `
            <div class="attacker-row">
                <span class="attacker-rank">#${i + 1}</span>
                <span class="attacker-ip">${escapeHtml(ip)}</span>
                <span class="attacker-count">${count} hits</span>
            </div>
        `;
    });
    container.innerHTML = html;
}

// ─── Credentials Table ──────────────────────────────────
function updateCredsTable(credentials) {
    const tbody = document.getElementById('credsBody');
    if (credentials.length === 0) {
        tbody.innerHTML = '<tr><td colspan="5" class="empty-cell">No credentials captured yet</td></tr>';
        return;
    }

    let html = '';
    for (const cred of credentials.slice(-30).reverse()) {
        const time = extractTime(cred.time);
        const user = cred.username || cred.post_body || '-';
        const pass = cred.password || '-';

        html += `
            <tr>
                <td>${time}</td>
                <td class="cred-ip">${escapeHtml(cred.ip || '?')}</td>
                <td class="cred-service">${cred.service || '?'}</td>
                <td class="cred-user">${escapeHtml(truncate(user, 30))}</td>
                <td class="cred-pass">${escapeHtml(truncate(pass, 30))}</td>
            </tr>
        `;
    }
    tbody.innerHTML = html;
}

// ─── Commands Table ──────────────────────────────────────
function updateCmdsTable(commands) {
    const tbody = document.getElementById('cmdsBody');
    if (commands.length === 0) {
        tbody.innerHTML = '<tr><td colspan="4" class="empty-cell">No commands captured yet</td></tr>';
        return;
    }

    let html = '';
    for (const cmd of commands.slice(-30).reverse()) {
        const time = extractTime(cmd.time);
        html += `
            <tr>
                <td>${time}</td>
                <td class="cred-ip">${escapeHtml(cmd.ip || '?')}</td>
                <td class="cred-service">${cmd.service || '?'}</td>
                <td class="cmd-text">${escapeHtml(truncate(cmd.command, 60))}</td>
            </tr>
        `;
    }
    tbody.innerHTML = html;
}

// ─── Live Feed ───────────────────────────────────────────
function updateLiveFeed(events) {
    if (feedCleared) return;

    const container = document.getElementById('liveFeed');
    if (events.length === 0) {
        container.innerHTML = '<div class="feed-empty">Waiting for connections...</div>';
        return;
    }

    // Only show last 80 events
    const recent = events.slice(-80);

    // Check if new events arrived
    if (recent.length > lastEventCount) {
        const newEvents = recent.slice(lastEventCount > 0 ? -(recent.length - lastEventCount + 10) : -80);
        let html = '';
        for (const ev of newEvents.reverse()) {
            html += renderFeedEvent(ev);
        }

        if (lastEventCount === 0) {
            container.innerHTML = html;
        } else {
            // Prepend new events
            container.insertAdjacentHTML('afterbegin',
                recent.slice(lastEventCount).reverse().map(renderFeedEvent).join('')
            );

            // Trim old events
            while (container.children.length > 80) {
                container.removeChild(container.lastChild);
            }
        }

        lastEventCount = recent.length;
    }
}

function clearFeed() {
    const container = document.getElementById('liveFeed');
    container.innerHTML = '<div class="feed-empty">Feed cleared — new events will appear here</div>';
    feedCleared = true;
    setTimeout(() => { feedCleared = false; lastEventCount = 0; }, 100);
}

// ─── Update Timer ────────────────────────────────────────
function updateTimer() {
    const el = document.getElementById('updateTimer');
    const seconds = Math.floor((Date.now() - lastUpdate) / 1000);
    el.textContent = `Updated ${seconds}s ago`;
}

// ─── Polling ─────────────────────────────────────────────
async function fetchData() {
    try {
        const [eventsRes, statsRes] = await Promise.all([
            fetch('/api/events'),
            fetch('/api/stats')
        ]);

        if (eventsRes.ok) {
            const events = await eventsRes.json();
            updateLiveFeed(events);
        }

        if (statsRes.ok) {
            const stats = await statsRes.json();
            updateStats(stats);
        }

        lastUpdate = Date.now();

        // Update status badge to green
        const badge = document.getElementById('statusBadge');
        badge.style.color = 'var(--green)';

    } catch (err) {
        console.error('Fetch error:', err);
        const badge = document.getElementById('statusBadge');
        badge.querySelector('span:last-child').textContent = 'OFFLINE';
        badge.style.color = 'var(--accent)';
    }
}

// ─── Init ────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
    fetchData();
    setInterval(fetchData, POLL_INTERVAL);
    setInterval(updateTimer, 1000);
});
