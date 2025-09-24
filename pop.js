const API = "http://127.0.0.1:5000";

function el(id){ return document.getElementById(id); }
function showOutput(txt){
  // accept string or object
  if (typeof txt === 'string') {
    el('output').innerText = txt;
  } else {
    el('output').innerText = JSON.stringify(txt, null, 2);
  }
}
function setStatus(txt){ el('status').innerText = txt; }

async function pollStatus(jobId) {
  setStatus("Scanning (background)...");
  const interval = setInterval(async () => {
    try {
      const resp = await fetch(`${API}/status/${jobId}`);
      if (!resp.ok) {
        clearInterval(interval);
        setStatus("Error checking status");
        return;
      }
      const j = await resp.json();
      setStatus(`Status: ${j.status} | Progress: ${j.progress}%`);

      if (j.quick_summary) {
        const q = j.quick_summary;
        showOutput(`Quick summary:\nURLs found (quick): ${q.urls_found_quick}\nOnion links (quick): ${ (q.onion_links_quick||[]).length }\nMissing headers (quick): ${Object.keys(q.missing_headers_quick || {}).length}\n\n`);
      }

      if (j.status === "done") {
        clearInterval(interval);
        setStatus("Scan complete. Fetching final result...");
        const res = await fetch(`${API}/result/${jobId}`);
        if (res.ok) {
          const full = await res.json();
          showOutput(full);
          if (j.result_file) {
            const dl = el('downloadLink');
            dl.href = `${API}/download/${j.result_file}`;
            dl.style.display = 'block';
            dl.innerText = 'Download full report';
          }
          setStatus("Done");
        } else {
          setStatus("Could not fetch final result");
        }
      } else if (j.status === "error") {
        clearInterval(interval);
        setStatus("Scan error");
        showOutput(j);
      }
    } catch (err) {
      clearInterval(interval);
      setStatus("Network error while polling");
      showOutput(err.message || String(err));
    }
  }, 2000);
}

async function scan() {
  const url = el('url').value.trim();
  if (!url) { alert('Enter URL'); return; }
  const active = document.querySelector('input[name="scanType"]:checked').value === 'active';
  const useTor = el('useTor').checked;

  setStatus("Starting...");

  try {
    const resp = await fetch(`${API}/scan`, {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({url, active, use_tor: useTor})
    });

    if (!resp.ok) {
      const err = await resp.json().catch(()=>({error: 'non-json error'}));
      setStatus("Error starting scan");
      showOutput("Error: " + (err.error || resp.status));
      return;
    }

    const data = await resp.json();
    const jobId = data.job_id;
    setStatus(`Job queued: ${jobId}`);
    showOutput("Quick summary:\n" + JSON.stringify(data.quick_summary, null, 2));
    pollStatus(jobId);
  } catch (e) {
    setStatus("Network/server error");
    showOutput(e.message || String(e));
  }
}

document.addEventListener('DOMContentLoaded', () => {
  el('scanBtn').addEventListener('click', scan);
});

