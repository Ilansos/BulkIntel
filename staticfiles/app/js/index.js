document.getElementById('check_abuseipdb').addEventListener('click', function() {
    checkIP('/check_ip/');
});
document.getElementById('check_virustotal').addEventListener('click', function() {
    checkIP('/check_ip_virustotal/');
});
document.getElementById('check_url_virustotal').addEventListener('click', function() {
    checkIP('/check_url_virustotal/');
});
document.getElementById('check_domain_virustotal').addEventListener('click', function() {
    checkIP('/check_domain_virustotal/');
});
document.getElementById('check_hash_virustotal').addEventListener('click', function() {
    checkIP('/check_hash_virustotal/');
});
document.getElementById('check_user_agent').addEventListener('click', function() {
    checkIP('/check_user_agent/');
});

function checkIP(url) {
    const ipData = document.getElementById('ip_input').value;
    const csrfToken = document.querySelector('[name=csrfmiddlewaretoken]').value;

    fetch(url, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
            'X-CSRFToken': csrfToken
        },
        body: new URLSearchParams({'ip_data': ipData})
    })
    .then(response => response.json())
    .then(data => {
        displayResults(data);
    })
    .catch(error => console.error('Error:', error));
}

function displayResults(data) {
    const resultsDiv = document.getElementById('results_table');
    resultsDiv.innerHTML = ''; // Clear previous results
    if (data && data.results) {
        const table = document.createElement('table');
        table.border = "1"; // Optional: for styling
        const headerRow = table.insertRow(0);
        const headerCell = headerRow.insertCell(0);
        headerCell.innerHTML = "<b>Results</b>"; // Optional: for styling
        data.results.forEach((result, index) => {
            const row = table.insertRow();
            const cell = row.insertCell();
            cell.textContent = result;
        });
        resultsDiv.appendChild(table);
    } else {
        resultsDiv.innerHTML = "No results found.";
    }
}
