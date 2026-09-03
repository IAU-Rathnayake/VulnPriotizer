const API_BASE_URL =
  "http://127.0.0.1:8000";

async function request(endpoint) {
  const response = await fetch(
    `${API_BASE_URL}${endpoint}`
  );

  if (!response.ok) {
    throw new Error(
      `API request failed with status ${response.status}`
    );
  }

  return response.json();
}

export function getDashboard() {
  return request("/dashboard");
}

export function getVulnerabilities() {
  return request("/vulnerabilities");
}