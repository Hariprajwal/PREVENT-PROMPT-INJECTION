const BASE_URL = "http://localhost:8001/api";

export const apiRequest = async (endpoint, method, body) => {
    const options = {
        method,
        headers: {
            "Content-Type": "application/json",
        },
    };

    if (method !== "GET" && body) {
        options.body = JSON.stringify(body);
    }

    const response = await fetch(`${BASE_URL}${endpoint}`, options);
    const data = await response.json();

    if (!response.ok) {
        return { ...data, _error: true, _status: response.status };
    }

    return data;
};
