let allAlerts = [];

async function loadDashboard() {
    try {
        const summaryRes = await fetch('/api/summary');
        const summary = await summaryRes.json();
        renderSummary(summary);
        renderAttackBreakdown(summary.attack_breakdown);
        renderSeverityDistribution(summary);

        const fpRes = await fetch('/api/fingerprint-summary');
        const fp = await fpRes.json();
        renderFingerprintPanel(fp);

        const alertsRes = await fetch('/api/alerts');
        allAlerts = await alertsRes.json();
        renderAlertsTable(allAlerts);

    } catch (err) {
        console.error('Failed to load dashboard:', err);
    }
}

function renderSummary(summary) {
    document.getElementById('summary-cards').innerHTML = `
        <div class="summary-card total">
            <div class="label">Total Flows Analyzed</div>
            <div class="value">${summary.total_flows}</div>
            <div class="delta">Live network traffic sample</div>
        </div>
        <div class="summary-card attacks">
            <div class="label">Attacks Detected</div>
            <div class="value">${summary.attacks_detected}</div>
            <div class="delta">${((summary.attacks_detected/summary.total_flows)*100).toFixed(1)}% of traffic</div>
        </div>
        <div class="summary-card high">
            <div class="label">High Severity</div>
            <div class="value">${summary.high_severity}</div>
            <div class="delta">${summary.pending_review} pending analyst review</div>
        </div>
        <div class="summary-card accuracy">
            <div class="label">Detection Accuracy</div>
            <div class="value">${summary.accuracy}%</div>
            <div class="delta">Validated against known labels</div>
        </div>
    `;
}

function renderAttackBreakdown(breakdown) {
    const maxCount = Math.max(...Object.values(breakdown), 1);
    let html = '';
    for (const [type, count] of Object.entries(breakdown)) {
        const pct = (count / maxCount) * 100;
        html += `
            <div class="attack-bar-row">
                <div class="attack-bar-label">${type}</div>
                <div class="attack-bar-track"><div class="attack-bar-fill" style="width:${pct}%"></div></div>
                <div class="attack-bar-count">${count}</div>
            </div>`;
    }
    document.getElementById('attack-breakdown').innerHTML = html || '<p style="color:#6b7280;font-size:13px;">No attacks detected</p>';
}

function renderSeverityDistribution(summary) {
    const items = [
        { label: 'High', count: summary.high_severity, color: '#ff6b6b' },
        { label: 'Medium', count: summary.medium_severity, color: '#ffb84f' },
        { label: 'Low', count: summary.low_severity, color: '#4fd98a' },
    ];
    document.getElementById('severity-distribution').innerHTML = items.map(item => `
        <div class="legend-item" style="margin-bottom:14px;">
            <span class="legend-dot" style="background:${item.color}"></span>
            ${item.label} — <strong style="color:#fff">${item.count}</strong>
        </div>`).join('');
}

function renderFingerprintPanel(fp) {
    const el = document.getElementById('fingerprint-panel');
    if (!el) return;
    if (fp.total_brute_force === 0) {
        el.innerHTML = '<p style="color:#6b7280;font-size:13px;">No Brute Force attacks to analyze</p>';
        return;
    }
    el.innerHTML = `
        <div class="fp-row">
            <div class="fp-bar-track">
                <div class="fp-bar-fill fp-automated" style="width:${fp.automated_pct}%"></div>
            </div>
            <div class="fp-label">🤖 Automated/Scripted: <strong>${fp.automated}</strong> (${fp.automated_pct}%)</div>
        </div>
        <div class="fp-row">
            <div class="fp-bar-track">
                <div class="fp-bar-fill fp-coordinated" style="width:${fp.coordinated_pct}%"></div>
            </div>
            <div class="fp-label">🌐 Irregular/Coordinated: <strong>${fp.coordinated}</strong> (${fp.coordinated_pct}%)</div>
        </div>
        <p class="fp-insight">
            ${fp.coordinated > 0
                ? `${fp.coordinated} Brute Force attack(s) show irregular timing patterns — possibly distributed across multiple sources. These warrant escalation beyond a simple single-IP block.`
                : `All detected Brute Force attacks show regular, automated timing — consistent with single-source scripted tools. Standard IP blocking should be effective.`}
        </p>
    `;
}

function severityBadge(severity) {
    const cls = severity ? severity.toLowerCase() : 'none';
    return `<span class="badge badge-${cls}">${severity}</span>`;
}

function renderAlertsTable(alerts) {
    document.getElementById('alerts-count').textContent = `${alerts.length} alerts`;
    if (alerts.length === 0) {
        document.getElementById('alerts-table-body').innerHTML = '<tr><td colspan="8" class="loading">No alerts detected</td></tr>';
        return;
    }
    document.getElementById('alerts-table-body').innerHTML = alerts.map(alert => {
        const confPct = (alert.confidence * 100).toFixed(1);
        const decisionTag = alert.analyst_decision
            ? `<span class="decision-tag decision-${alert.analyst_decision}">${alert.analyst_decision.replace('_',' ')}</span>`
            : `<span class="decision-tag decision-pending">Pending</span>`;
        return `
            <tr onclick="openModal(${alert.id})">
                <td>#${alert.id}</td>
                <td><strong>${alert.predicted_class}</strong></td>
                <td><span class="confidence-bar"><span class="confidence-fill" style="width:${confPct}%"></span></span>${confPct}%</td>
                <td>${alert.is_anomalous ? '⚠️ Yes' : '— No'}</td>
                <td style="font-size:12px;">${alert.behavior_cluster}</td>
                <td>${severityBadge(alert.severity)}</td>
                <td>${decisionTag}</td>
            </tr>`;
    }).join('');
}

function openModal(alertId) {
    const alert = allAlerts.find(a => a.id === alertId);
    if (!alert) return;

    document.getElementById('modal-title').textContent = `Flow #${alert.id} — ${alert.predicted_class}`;

    document.getElementById('modal-detail-grid').innerHTML = `
        <div class="detail-item"><div class="dlabel">Predicted Class</div><div class="dvalue">${alert.predicted_class}</div></div>
        <div class="detail-item"><div class="dlabel">True Label</div><div class="dvalue">${alert.true_label}</div></div>
        <div class="detail-item"><div class="dlabel">Confidence</div><div class="dvalue">${(alert.confidence*100).toFixed(1)}%</div></div>
        <div class="detail-item"><div class="dlabel">Anomaly Score</div><div class="dvalue">${alert.anomaly_score}</div></div>
        <div class="detail-item"><div class="dlabel">Behavioral Fingerprint</div><div class="dvalue" style="font-size:12px;">${alert.behavior_cluster}</div></div>
        <div class="detail-item"><div class="dlabel">Severity</div><div class="dvalue">${severityBadge(alert.severity)}</div></div>
    `;

    document.getElementById('modal-top-features').innerHTML = `
        <strong>Key indicators driving this prediction:</strong>
        <ul class="feature-list">${alert.top_features.map(f => `<li>${f}</li>`).join('')}</ul>
    `;

    document.getElementById('modal-reasoning').innerHTML = alert.reasoning_trace
        .map((step, i) => `<div class="reasoning-step">${i+1}. ${step}</div>`).join('');

    document.getElementById('modal-action').innerHTML = `🎯 <strong>Recommended Action:</strong> ${alert.action}`;

    document.getElementById('modal-decision-buttons').dataset.alertId = alert.id;
    updateDecisionButtonsUI(alert.analyst_decision);

    document.getElementById('modal-overlay').classList.add('active');
}

function updateDecisionButtonsUI(currentDecision) {
    document.querySelectorAll('.decision-btn').forEach(btn => {
        btn.classList.toggle('active', btn.dataset.value === currentDecision);
    });
}

async function makeDecision(decision) {
    const alertId = parseInt(document.getElementById('modal-decision-buttons').dataset.alertId);
    await fetch(`/api/alert/${alertId}/decide`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ decision })
    });
    const alert = allAlerts.find(a => a.id === alertId);
    alert.analyst_decision = decision;
    updateDecisionButtonsUI(decision);
    renderAlertsTable(allAlerts);
}

function closeModal() {
    document.getElementById('modal-overlay').classList.remove('active');
}

document.getElementById('modal-overlay').addEventListener('click', (e) => {
    if (e.target.id === 'modal-overlay') closeModal();
});

loadDashboard();