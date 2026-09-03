const API_BASE_URL =
  "http://127.0.0.1:8000";


async function request(endpoint) {
  const response = await fetch(
    `${API_BASE_URL}${endpoint}`
  );

  if (!response.ok) {
    let message =
      `API request failed with status ${response.status}`;

    try {
      const errorData =
        await response.json();

      if (errorData.detail) {
        message =
          typeof errorData.detail === "string"
            ? errorData.detail
            : JSON.stringify(
                errorData.detail
              );
      }
    } catch {
      // Keep the original error message.
    }

    throw new Error(message);
  }

  return response.json();
}


export function getDashboard() {
  return request("/dashboard");
}


export function getVulnerabilities() {
  return request("/vulnerabilities");
}


export function getModelInfo() {
  return request("/model-info");
}

export function getAnalytics() {
  return request("/analytics");
}
