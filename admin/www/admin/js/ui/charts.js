/**
 * Charts Module - Handles ShieldDNS visualizations and interactivity
 */
import { createGradient } from './helpers.js';
import { state } from '../core/state.js';

let trafficChart = null;
let typeChart = null;
let clientChart = null;
let latencyChart = null;

const isChartAvailable = () => {
    if (typeof Chart === 'undefined') {
        console.error('Chart.js library is not loaded. Ensure you have an active internet connection and that cdn.jsdelivr.net is not blocked.');
        return false;
    }
    return true;
};

export const renderTrafficChart = (data, onClickHour) => {
    if (!isChartAvailable()) return;
    const canvas = document.getElementById('traffic-chart');
    if (!canvas) return;
    const ctx = canvas.getContext('2d');

    // Align data to the last 24 hours precisely
    const now = new Date();
    const labels = [];
    const totals = [];
    const blocked = [];

    for (let i = 23; i >= 0; i--) {
        const d = new Date(now.getTime() - i * 60 * 60 * 1000);
        const h = d.getHours();
        const hourStr = `${h}:00`;
        labels.push(hourStr);

        // Find match in backend data using the time field
        const match = (data || []).find(p => {
            if (!p.time) return false;
            const pd = new Date(p.time);
            return pd.getHours() === h && pd.getDate() === d.getDate();
        });

        totals.push(match ? match.total : 0);
        blocked.push(match ? match.blocked : 0);
    }

    const totalColor = 'rgba(92, 107, 192, 1)';
    const blockedColor = 'rgba(239, 68, 68, 1)';

    if (trafficChart) {
        trafficChart.data.datasets[0].data = totals;
        trafficChart.data.datasets[1].data = blocked;
        trafficChart.update();
        return;
    }

    trafficChart = new Chart(ctx, {
        type: 'line',
        data: {
            labels: labels,
            datasets: [
                {
                    label: 'Total Queries',
                    data: totals,
                    borderColor: totalColor,
                    backgroundColor: createGradient(ctx, totalColor),
                    fill: true,
                    tension: 0.4,
                    borderWidth: 3,
                    pointRadius: 0,
                    pointHoverRadius: 6,
                    pointBackgroundColor: totalColor,
                    pointBorderColor: '#fff',
                    pointBorderWidth: 2
                },
                {
                    label: 'Blocked',
                    data: blocked,
                    borderColor: blockedColor,
                    backgroundColor: createGradient(ctx, blockedColor),
                    fill: true,
                    tension: 0.4,
                    borderWidth: 3,
                    pointRadius: 0,
                    pointHoverRadius: 6,
                    pointBackgroundColor: blockedColor,
                    pointBorderColor: '#fff',
                    pointBorderWidth: 2
                }
            ]
        },
        options: {
            animation: {
                duration: 1200,
                easing: 'easeOutQuart'
            },
            onClick: (e, activeEls) => {
                if (activeEls.length > 0 && onClickHour) {
                    const idx = activeEls[0].index;
                    const hourLabel = labels[idx];
                    onClickHour(hourLabel);
                }
            },
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: { display: false },
                tooltip: {
                    mode: 'index',
                    intersect: false,
                    backgroundColor: 'rgba(15, 23, 42, 0.9)',
                    padding: 12,
                    cornerRadius: 8
                }
            },
            scales: {
                y: { 
                    beginAtZero: true, 
                    grid: { color: 'rgba(255,255,255,0.03)', drawBorder: false }, 
                    ticks: { color: '#64748b', font: { size: 11 } } 
                },
                x: { 
                    grid: { display: false }, 
                    ticks: { color: '#64748b', font: { size: 11 }, maxRotation: 0 } 
                }
            }
        }
    });
};

export const renderTypeChart = (queryTypes, onClickType) => {
    if (!isChartAvailable()) return;
    const ctx = document.getElementById('type-chart')?.getContext('2d');
    if (!ctx) return;

    let labels = Object.keys(queryTypes);
    let data = Object.values(queryTypes);

    if (labels.length === 0) {
        labels = ['No Data'];
        data = [1];
    }

    const bgColors = labels.map((l, i) => (window.DNS_TYPE_COLORS || {})[l] || `hsla(${(i * 137.5) % 360}, 65%, 60%, 0.85)`);

    if (typeChart) {
        typeChart.data.labels = labels;
        typeChart.data.datasets[0].data = data;
        typeChart.data.datasets[0].backgroundColor = bgColors;
        typeChart.update();
        return;
    }

    typeChart = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: labels,
            datasets: [{
                data: data,
                backgroundColor: bgColors,
                hoverOffset: 15,
                borderWidth: 0,
                borderRadius: 4
            }]
        },
        options: {
            onClick: (e, activeEls) => {
                if (activeEls.length > 0 && onClickType) {
                    const idx = activeEls[0].index;
                    onClickType(labels[idx]);
                }
            },
            responsive: true,
            maintainAspectRatio: false,
            cutout: '72%',
            plugins: {
                legend: {
                    position: 'bottom',
                    labels: { 
                        color: '#94a3b8', 
                        boxWidth: 8, 
                        padding: 15,
                        usePointStyle: true,
                        pointStyle: 'circle',
                        font: { size: 11, weight: '500' } 
                    }
                },
                tooltip: {
                    backgroundColor: 'rgba(15, 23, 42, 0.9)',
                    padding: 12,
                    cornerRadius: 8,
                    callbacks: {
                        label: (context) => ` ${context.label}: ${context.parsed.toLocaleString()} queries`
                    }
                }
            }
        }
    });
};

export const renderClientChart = (canvas, data, blocked) => {
    if (!isChartAvailable()) return;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    
    // Last 24 hours labels
    const labels = Array.from({ length: 24 }, (_, i) => {
        const h = (new Date().getHours() - 23 + i + 24) % 24;
        return `${h}:00`;
    });

    const totalColor = 'rgba(92, 107, 192, 1)';
    const blockedColor = 'rgba(239, 68, 68, 1)';

    if (clientChart) {
        clientChart.data.datasets[0].data = data;
        clientChart.data.datasets[1].data = blocked;
        clientChart.update();
        return;
    }

    clientChart = new Chart(ctx, {
        type: 'line',
        data: {
            labels: labels,
            datasets: [
                {
                    label: 'Total',
                    data: data,
                    borderColor: totalColor,
                    backgroundColor: createGradient(ctx, totalColor),
                    fill: true,
                    tension: 0.4,
                    borderWidth: 2,
                    pointRadius: 0
                },
                {
                    label: 'Blocked',
                    data: blocked,
                    borderColor: blockedColor,
                    backgroundColor: createGradient(ctx, blockedColor),
                    fill: true,
                    tension: 0.4,
                    borderWidth: 2,
                    pointRadius: 0
                }
            ]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: { display: false },
                tooltip: { mode: 'index', intersect: false }
            },
            scales: {
                y: { beginAtZero: true, display: false },
                x: { display: false }
            }
        }
    });
};

let countryChart = null;
export const renderCountryChart = (countryData, onClickCountry) => {
    if (!isChartAvailable()) return;
    const ctx = document.getElementById('country-chart')?.getContext('2d');
    if (!ctx) return;

    // Filter out unresolved ('-') entries — never show 'Resolving...' in the chart
    const filteredEntries = Object.entries(countryData).filter(([code]) => code !== '-' && code !== '');
    let labels = filteredEntries.map(([code]) => {
        if (code === 'geo') return 'Local Environment';
        return (state.allCountries || {})[code] || code;
    });
    let data = filteredEntries.map(([, v]) => v);

    if (labels.length === 0) {
        labels = ['No Data'];
        data = [1];
    }

    const bgColors = labels.map((l, i) => `hsla(${(i * 95) % 360}, 60%, 55%, 0.85)`);

    if (countryChart) {
        countryChart.data.labels = labels;
        countryChart.data.datasets[0].data = data;
        countryChart.data.datasets[0].backgroundColor = bgColors;
        countryChart.update();
        return;
    }

    countryChart = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: labels,
            datasets: [{
                data: data,
                backgroundColor: bgColors,
                hoverOffset: 15,
                borderWidth: 0,
                borderRadius: 4
            }]
        },
        options: {
            onClick: (e, activeEls) => {
                if (activeEls.length > 0 && onClickCountry) {
                    const idx = activeEls[0].index;
                    onClickCountry(labels[idx]);
                }
            },
            responsive: true,
            maintainAspectRatio: false,
            cutout: '72%',
            plugins: {
                legend: {
                    position: 'bottom',
                    labels: { 
                        color: '#94a3b8', 
                        boxWidth: 8, 
                        padding: 15,
                        usePointStyle: true,
                        pointStyle: 'circle',
                        font: { size: 11, weight: '500' } 
                    }
                },
                tooltip: {
                    backgroundColor: 'rgba(15, 23, 42, 0.9)',
                    padding: 12,
                    cornerRadius: 8,
                    callbacks: {
                        label: (context) => ` ${context.label}: ${context.parsed.toLocaleString()} requests`
                    }
                }
            }
        }
    });
};
