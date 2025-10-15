const STATUS_ORDER = ['valid', 'blocked', 'verification'];

document.addEventListener('DOMContentLoaded', () => {
    const canvas = document.getElementById('loginChart');
    let chartInstance = null;

    if (canvas && typeof Chart !== 'undefined' && window.chartCounts) {
        const labels = STATUS_ORDER.map((key) => key.charAt(0).toUpperCase() + key.slice(1));
        const values = STATUS_ORDER.map((key) => window.chartCounts[key] ?? 0);

        chartInstance = new Chart(canvas, {
            type: 'doughnut',
            data: {
                labels,
                datasets: [{
                    label: 'Login Attempts',
                    data: values,
                    backgroundColor: ['#198754', '#dc3545', '#ffc107'],
                    borderWidth: 1,
                }],
            },
            options: {
                responsive: true,
                plugins: {
                    legend: {
                        position: 'bottom',
                    },
                    tooltip: {
                        backgroundColor: '#1f2933',
                        callbacks: {
                            label: (context) => {
                                const label = context.label || '';
                                const value = context.formattedValue || '0';
                                return `${label}: ${value}`;
                            },
                        },
                    },
                },
                animation: {
                    animateRotate: true,
                    duration: 800,
                },
            },
        });

        window.loginChart = chartInstance;
    }

    initActivityTable(chartInstance);
});

function initActivityTable(chartInstance) {
    const tableBody = document.getElementById('activity-table-body');
    if (!tableBody) {
        return;
    }

    const pageSizeSelect = document.getElementById('activity-page-size');
    const prevButton = document.getElementById('activity-prev');
    const nextButton = document.getElementById('activity-next');
    const pageInfo = document.getElementById('activity-page-info');
    const totalAttemptsEl = document.getElementById('total-attempts');
    const lastAttemptEl = document.getElementById('last-attempt');

    const state = {
        page: 1,
        pageSize: parseInt(pageSizeSelect?.value ?? '10', 10) || 10,
        totalPages: 1,
        total: 0,
    };

    let isFetching = false;
    let pendingRefresh = false;

    function setLoadingRow(message = 'Loading activity…') {
        tableBody.innerHTML = '';
        const row = document.createElement('tr');
        const cell = document.createElement('td');
        cell.colSpan = 6;
        cell.className = 'text-center text-muted';
        cell.textContent = message;
        row.appendChild(cell);
        tableBody.appendChild(row);
    }

    function formatTimestamp(value) {
        if (!value) {
            return 'Unknown';
        }
        const isoLike = value.replace(' ', 'T');
        const date = new Date(isoLike);
        if (Number.isNaN(date.getTime())) {
            return value;
        }
        return date.toLocaleString(undefined, {
            month: 'short',
            day: 'numeric',
            year: 'numeric',
            hour: 'numeric',
            minute: '2-digit',
            hour12: true,
        });
    }

    function prettyContext(raw) {
        if (!raw) {
            return '';
        }
        try {
            const parsed = JSON.parse(raw);
            return JSON.stringify(parsed, null, 2);
        } catch (err) {
            return raw;
        }
    }

    function createStatusBadge(status) {
        const badge = document.createElement('span');
        const normalized = (status || '').toLowerCase();
        let cls = 'bg-secondary';
        if (normalized === 'valid') {
            cls = 'bg-success';
        } else if (normalized === 'blocked') {
            cls = 'bg-danger';
        } else if (normalized === 'verification') {
            cls = 'bg-warning text-dark';
        }
        badge.className = `badge ${cls}`;
        badge.textContent = normalized ? normalized.charAt(0).toUpperCase() + normalized.slice(1) : 'Unknown';
        return badge;
    }

    function renderRows(logs) {
        tableBody.innerHTML = '';

        if (!Array.isArray(logs) || logs.length === 0) {
            const row = document.createElement('tr');
            const cell = document.createElement('td');
            cell.colSpan = 6;
            cell.className = 'text-center text-muted';
            cell.textContent = 'No login activity recorded yet.';
            row.appendChild(cell);
            tableBody.appendChild(row);
            return;
        }

        logs.forEach((log) => {
            const row = document.createElement('tr');

            // Timestamp
            const tsTd = document.createElement('td');
            tsTd.textContent = formatTimestamp(log.login_time);
            row.appendChild(tsTd);

            // User info
            const userTd = document.createElement('td');
            const knownEmail = (log.known_email || '').trim();
            const submittedEmail = (log.submitted_email || '').trim();

            if (knownEmail) {
                const primary = document.createElement('span');
                primary.textContent = knownEmail;
                userTd.appendChild(primary);

                if (submittedEmail && submittedEmail.toLowerCase() !== knownEmail.toLowerCase()) {
                    const secondary = document.createElement('span');
                    secondary.className = 'text-muted small d-block';
                    secondary.textContent = `Entered: ${submittedEmail}`;
                    userTd.appendChild(secondary);
                }
            } else if (submittedEmail) {
                const primary = document.createElement('span');
                primary.textContent = submittedEmail;
                userTd.appendChild(primary);

                const secondary = document.createElement('span');
                secondary.className = 'text-muted small d-block';
                secondary.textContent = 'Unlinked attempt';
                userTd.appendChild(secondary);
            } else {
                const unknown = document.createElement('span');
                unknown.className = 'text-muted small';
                unknown.textContent = 'Unknown user';
                userTd.appendChild(unknown);
            }
            row.appendChild(userTd);

            // IP address
            const ipTd = document.createElement('td');
            ipTd.textContent = log.ip_address || '—';
            row.appendChild(ipTd);

            // Browser agent
            const agentTd = document.createElement('td');
            const agentSpan = document.createElement('span');
            agentSpan.className = 'd-inline-block text-truncate';
            agentSpan.style.maxWidth = '220px';
            agentSpan.title = log.browser_agent || '';
            agentSpan.textContent = log.browser_agent || 'Unknown';
            agentTd.appendChild(agentSpan);
            row.appendChild(agentTd);

            // Status
            const statusTd = document.createElement('td');
            statusTd.appendChild(createStatusBadge(log.status));
            row.appendChild(statusTd);

            // Risk
            const riskTd = document.createElement('td');
            if (log.risk_score !== null && log.risk_score !== undefined) {
                const riskWrapper = document.createElement('div');
                riskWrapper.className = 'd-flex flex-column small';

                const scoreLine = document.createElement('span');
                scoreLine.textContent = Number.parseFloat(log.risk_score).toFixed(3);
                riskWrapper.appendChild(scoreLine);

                const decisionLine = document.createElement('span');
                decisionLine.className = 'text-muted';
                decisionLine.textContent = log.risk_decision || 'n/a';
                riskWrapper.appendChild(decisionLine);

                riskTd.appendChild(riskWrapper);
            } else {
                const na = document.createElement('span');
                na.className = 'text-muted small d-block';
                na.textContent = 'n/a';
                riskTd.appendChild(na);
            }

            if (log.context_json) {
                const details = document.createElement('details');
                details.className = 'mt-1';

                const summary = document.createElement('summary');
                summary.className = 'text-muted small';
                summary.textContent = 'Context';
                details.appendChild(summary);

                const pre = document.createElement('pre');
                pre.className = 'small bg-light border rounded p-2 mb-0';
                pre.textContent = prettyContext(log.context_json);
                details.appendChild(pre);

                riskTd.appendChild(details);
            }

            row.appendChild(riskTd);
            tableBody.appendChild(row);
        });
    }

    function updatePagination(page, totalPages, total) {
        state.page = page;
        state.totalPages = totalPages;
        state.total = total;

        const safeTotalPages = Math.max(1, totalPages || 1);
        pageInfo.textContent = `Page ${page} of ${safeTotalPages}`;

        prevButton.disabled = page <= 1;
        nextButton.disabled = page >= safeTotalPages || total === 0;
    }

    function updateMetrics(payload) {
        if (payload.status_counts) {
            const counts = payload.status_counts;
            const totals = STATUS_ORDER.map((key) => counts[key] ?? 0);
            const totalAttempts = totals.reduce((acc, value) => acc + value, 0);

            if (totalAttemptsEl) {
                totalAttemptsEl.textContent = totalAttempts;
            }

            if (chartInstance) {
                chartInstance.data.datasets[0].data = totals;
                chartInstance.update('none');
            }

            window.chartCounts = counts;
        }

        if (lastAttemptEl) {
            if (payload.last_login) {
                lastAttemptEl.textContent = formatTimestamp(payload.last_login);
            } else {
                lastAttemptEl.textContent = 'No activity yet';
            }
        }
    }

    async function loadData({ silent = false } = {}) {
        if (isFetching) {
            pendingRefresh = true;
            return;
        }
        isFetching = true;
        if (!silent) {
            setLoadingRow();
        }

        try {
            const params = new URLSearchParams({
                page: String(state.page),
                pageSize: String(state.pageSize),
                _: Date.now().toString(),
            });

            const response = await fetch(`activity_feed.php?${params.toString()}`, { cache: 'no-store' });
            if (!response.ok) {
                throw new Error(`Request failed with status ${response.status}`);
            }

            const payload = await response.json();
            const totalPages = payload.total_pages || 1;
            if (state.page > totalPages && payload.total > 0) {
                state.page = totalPages;
                isFetching = false;
                return loadData({ silent: false });
            }

            renderRows(payload.data);
            updatePagination(payload.page || state.page, totalPages, payload.total || 0);
            updateMetrics(payload);
        } catch (error) {
            tableBody.innerHTML = '';
            const row = document.createElement('tr');
            const cell = document.createElement('td');
            cell.colSpan = 6;
            cell.className = 'text-center text-danger';
            cell.textContent = 'Failed to load activity feed.';
            row.appendChild(cell);
            tableBody.appendChild(row);
            console.error('[activity] fetch failed', error);
        } finally {
            isFetching = false;
            if (pendingRefresh) {
                pendingRefresh = false;
                loadData({ silent: true });
            }
        }
    }

    pageSizeSelect?.addEventListener('change', () => {
        state.pageSize = parseInt(pageSizeSelect.value, 10) || 10;
        state.page = 1;
        loadData();
    });

    prevButton?.addEventListener('click', () => {
        if (state.page > 1) {
            state.page -= 1;
            loadData();
        }
    });

    nextButton?.addEventListener('click', () => {
        if (state.page < state.totalPages) {
            state.page += 1;
            loadData();
        }
    });

    loadData();
    setInterval(() => loadData({ silent: true }), 3000);
}
