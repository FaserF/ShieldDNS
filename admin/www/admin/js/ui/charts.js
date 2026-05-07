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
    const ctx = document.getElementById('traffic-chart').getContext('2d');
    const labels = [];
    const allowed = [];
    const blocked = [];
    
    const now = new Date();
    // Generate exactly 24 hour slots ending now
    for (let i = 23; i >= 0; i--) {
        const d = new Date(now.getTime() - i * 60 * 60 * 1000);
        const h = d.getHours();
        const hourStr = `${h}:00`;
        labels.push(hourStr);
        
        // Find match in data
        const startOfHour = new Date(d);
        startOfHour.setMinutes(0, 0, 0);
        
        const match = (data || []).find(p => {
            if (!p.time) return false;
            const pd = new Date(p.time);
            const pStartOfHour = new Date(pd);
            pStartOfHour.setMinutes(0, 0, 0);
            return pStartOfHour.getTime() === startOfHour.getTime();
        });
        
        allowed.push(match ? match.allowed : 0);
        blocked.push(match ? match.blocked : 0);
    }

    const allowedColor = 'rgba(99, 102, 241, 1)'; // Indigo
    const blockedColor = 'rgba(239, 68, 68, 1)'; // Red

    if (trafficChart) {
        trafficChart.data.labels = labels;
        trafficChart.data.datasets[0].data = allowed;
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
                    label: 'Allowed Queries',
                    data: allowed,
                    borderColor: allowedColor,
                    backgroundColor: 'rgba(99, 102, 241, 0.2)',
                    borderWidth: 2,
                    tension: 0.4,
                    fill: true,
                    pointRadius: 0,
                    pointHoverRadius: 4,
                },
                {
                    label: 'Blocked Queries',
                    data: blocked,
                    borderColor: blockedColor,
                    backgroundColor: 'rgba(239, 68, 68, 0.6)',
                    borderWidth: 2,
                    tension: 0.4,
                    fill: true,
                    pointRadius: 0,
                    pointHoverRadius: 4,
                }
            ]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    display: true,
                    position: 'top',
                    align: 'end',
                    labels: {
                        color: '#94a3b8',
                        usePointStyle: true,
                        pointStyle: 'circle',
                        padding: 20,
                        font: { size: 11 }
                    }
                },
                tooltip: {
                    mode: 'index',
                    intersect: false,
                    backgroundColor: 'rgba(15, 23, 42, 0.9)',
                    titleColor: '#fff',
                    bodyColor: '#cbd5e1',
                    borderColor: 'rgba(255, 255, 255, 0.1)',
                    borderWidth: 1,
                    padding: 12,
                    displayColors: true,
                    callbacks: {
                        label: function(context) {
                            let label = context.dataset.label || '';
                            if (label) {
                                label += ': ';
                            }
                            if (context.parsed.y !== null) {
                                label += context.parsed.y.toLocaleString();
                            }
                            return label;
                        },
                        footer: (tooltipItems) => {
                            let total = 0;
                            tooltipItems.forEach(function(tooltipItem) {
                                total += tooltipItem.parsed.y;
                            });
                            return 'Total: ' + total.toLocaleString();
                        }
                    }
                }
            },
            scales: {
                y: {
                    stacked: true,
                    beginAtZero: true,
                    grid: { color: 'rgba(255, 255, 255, 0.05)' },
                    ticks: { 
                        color: '#64748b', 
                        font: { size: 10 },
                        callback: value => value.toLocaleString()
                    }
                },
                x: {
                    stacked: true,
                    grid: { display: false },
                    ticks: { color: '#64748b', font: { size: 10 }, maxRotation: 0 }
                }
            },
            interaction: {
                mode: 'nearest',
                axis: 'x',
                intersect: false
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
