import { useAuthStore } from "../stores/auth";

let isRefreshing = false;
let refreshPromise: Promise<boolean> | null = null;

async function refreshAccessToken(): Promise<boolean> {
  if (isRefreshing && refreshPromise) {
    return refreshPromise;
  }

  isRefreshing = true;
  refreshPromise = (async () => {
    try {
      const response = await fetch("/api/v1/public/refresh-token", {
        method: "POST",
        credentials: "include",
      });

      if (response.ok) {
        console.log("Access token refreshed successfully");
        return true;
      } else {
        console.log("Failed to refresh access token");
        return false;
      }
    } catch (error) {
      console.error("Error refreshing access token:", error);
      return false;
    } finally {
      isRefreshing = false;
      refreshPromise = null;
    }
  })();

  return refreshPromise;
}

export async function fetchWithAuth(
  url: string | URL | globalThis.Request,
  options: Omit<RequestInit, "credentials"> = {}
): Promise<Response> {
  let response = await fetch(url, {
    ...options,
    credentials: "include", // Ensure cookies are included
  });

  if (response.status === 401) {
    // Try to refresh the access token
    const refreshSuccess = await refreshAccessToken();
    
    if (refreshSuccess) {
      // Retry the original request with the new access token
      response = await fetch(url, {
        ...options,
        credentials: "include",
      });
    }

    // If refresh failed or the retry still returns 401, logout
    if (!refreshSuccess || response.status === 401) {
      console.log("Unauthorized, logging out");
      useAuthStore.getState().useLogout();
    }
  }

  return response;
}

export async function fetchSecureTest() {
  const response = await fetchWithAuth("/api/v1/example/jwt");
  if (response.ok) {
    const data = await response.json();
  }
}
