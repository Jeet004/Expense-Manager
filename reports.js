function generateComparativeAnalysis() {
    const ctx = document.getElementById('comparativeChart').getContext('2d');
    new Chart(ctx, {
        type: 'bar',
        data: {
            labels: categories,
            datasets: [
                {
                    label: 'Current Month',
                    data: currentMonthData,
                    backgroundColor: '#36A2EB'
                },
                {
                    label: 'Previous Month',
                    data: previousMonthData,
                    backgroundColor: '#FF6384'
                }
            ]
        },
        options: {
            responsive: true,
            scales: {
                y: {
                    beginAtZero: true
                }
            }
        }
    });
}