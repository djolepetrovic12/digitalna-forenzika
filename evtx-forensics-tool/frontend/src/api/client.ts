const apiBaseUrl = import.meta.env.VITE_API_BASE_URL ?? 'http://127.0.0.1:8000';

export const apiClient = {
  get: async <T>(url: string): Promise<T> => {
    const response = await fetch(`${apiBaseUrl}${url}`);
    if (!response.ok) {
      throw new Error(`API request failed: ${response.status}`);
    }
    return (await response.json()) as T;
  },
  postFile: async <T>(url: string, body: FormData): Promise<T> => {
    const response = await fetch(`${apiBaseUrl}${url}`, { method: 'POST', body });
    if (!response.ok) {
      const bodyText = await response.text();
      let detail: string | undefined;
      try {
        const payload = JSON.parse(bodyText) as { detail?: string };
        detail = payload.detail;
      } catch {
        detail = undefined;
      }
      throw new Error(detail || bodyText || `API request failed: ${response.status}`);
    }
    return (await response.json()) as T;
  },
  post: async <T>(url: string, body: unknown): Promise<T> => {
    const response = await fetch(`${apiBaseUrl}${url}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
    if (!response.ok) throw new Error(`API request failed: ${response.status}`);
    return (await response.json()) as T;
  },
};
