document.addEventListener('DOMContentLoaded', () => {
    const canvas = document.getElementById('loginChart');
    if (!canvas || typeof Chart === 'undefined' || !window.chartCounts) {
        return;
    }

    const chartCounts = window.chartCounts;
    const labels = Object.keys(chartCounts).map((key) => {
        return key.charAt(0).toUpperCase() + key.slice(1);
    });
    const values = Object.keys(chartCounts).map((key) => chartCounts[key]);

    new Chart(canvas, {
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
});
