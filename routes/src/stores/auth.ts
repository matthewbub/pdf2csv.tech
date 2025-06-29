import importBankStatementStore from "@/components/ImportBankStatementApp/ImportBankStatement.store";
import { fetchWithAuth } from "@/utils/auth-helpers";
import { validateResponse } from "@/utils/schema-validator";
import { create } from "zustand";

interface NullTime {
  time: Date | null;
  valid: boolean;
}

type AuthStore = {
  isAuthenticated: boolean;
  isLoading: boolean;
  isInitializing: boolean;
  isSecurityQuestionsAnswered: boolean;
  error: string | null;
  user: {
    id: string;
    username: string;
    email: string;
    applicationEnvironmentRole: string;
    securityQuestionsAnswered: boolean;
    inactiveAt: NullTime;
  } | null;
  checkAuth: () => Promise<boolean>;
  useLogin: (username: string, password: string) => Promise<void>;
  useLogout: () => Promise<void>;
  useSignup: (
    username: string,
    email: string,
    password: string,
    confirmPassword: string,
    termsAccepted: boolean
  ) => Promise<void>;
  useSecurityQuestions: (
    questions: { question: string; answer: string }[]
  ) => Promise<void>;
  isSessionExpiring: boolean;
  sessionTimeRemaining: number;
  renewSession: () => Promise<void>;
  setSessionExpiring: (expiring: boolean, timeRemaining?: number) => void;
  setDisplayLoginModal: (display: boolean) => void;
  displayLoginModal: boolean;
  pagesProcessed: number;
  setPagesProcessed: () => Promise<void>;
};

export const useAuthStore = create<AuthStore>((set) => ({
  isInitializing: true,
  isAuthenticated: false,
  isLoading: false,
  isSecurityQuestionsAnswered: false,
  error: null,
  user: null,
  checkAuth: async () => {
    try {
      set({ isLoading: true, error: null });
      const response = await fetch("/api/v1/account/auth-check", {
        credentials: "include",
      });
      const json = await response.json();

      if (json.ok && json?.data?.tokenExpiresIn > 0) {
        if (json?.data?.inactiveAt?.Valid) {
          set({
            error: "This account has been deactivated. Please contact support.",
            isAuthenticated: false,
            user: null,
          });
          return false;
        }

        set({
          isAuthenticated: true,
          user: {
            id: json?.data?.id ?? "",
            username: json?.data?.username ?? "",
            email: json?.data?.email ?? "",
            applicationEnvironmentRole:
              json?.data?.applicationEnvironmentRole ?? "",
            securityQuestionsAnswered:
              json?.data?.securityQuestionsAnswered || false,
            inactiveAt: {
              valid: json?.data?.inactiveAt?.Valid || false,
              time: json?.data?.inactiveAt?.value || null,
            },
          },
          error: null,
        });

        if (json?.data?.tokenExpiresIn && json?.data?.tokenExpiresIn < 300) {
          // 5 minutes
          set({
            isSessionExpiring: true,
            sessionTimeRemaining: json?.data?.tokenExpiresIn,
          });
        }

        return true;
      } else {
        set({
          isAuthenticated: false,
          user: null,
          isSecurityQuestionsAnswered: false,
        });

        return false;
      }
    } catch (error) {
      set({
        isAuthenticated: false,
        user: null,
        isSecurityQuestionsAnswered: false,
      });

      return false;
    } finally {
      set({ isLoading: false, isInitializing: false });
    }
  },

  useLogin: async (username: string, password: string) => {
    try {
      set({ isLoading: true, error: null });
      const response = await fetch("/api/v1/public/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        credentials: "include",
        body: JSON.stringify({ username, password }),
      });
      const json = (await response.json()) as {
        ok: boolean;
        message: string;
        securityQuestionsAnswered?: boolean;
      };

      if (json.ok) {
        set({
          isAuthenticated: true,
          isSecurityQuestionsAnswered: json?.securityQuestionsAnswered ?? false,
          error: null,

          // close the login modal if it was used to login
          displayLoginModal: false,
        });

        // dismiss the ImportBankStatement Errors
        importBankStatementStore.getState().setError("");
      } else {
        set({
          error: json.message || "Invalid username or password",
          isAuthenticated: false,
          user: null,
          isSecurityQuestionsAnswered: false,
        });
      }
    } catch (error) {
      set({
        error: "An error occurred during login",
        isAuthenticated: false,
        user: null,
        isSecurityQuestionsAnswered: false,
      });
    } finally {
      set({ isLoading: false });
    }
  },

  useLogout: async () => {
    try {
      set({ isLoading: true });
      const response = await fetch("/api/v1/account/logout", {
        method: "POST",
        credentials: "include",
      });
      const json = await response.json();

      if (json.ok) {
        set({
          isAuthenticated: false,
          user: null,
          isSecurityQuestionsAnswered: false,
        });
      } else {
        set({
          error: "An error occurred during logout",
          user: null,
          isSecurityQuestionsAnswered: false,
          isAuthenticated: false,
        });
      }
    } catch (error) {
      set({
        error: "An error occurred during logout",
        user: null,
        isSecurityQuestionsAnswered: false,
        isAuthenticated: false,
      });
    } finally {
      set({ isLoading: false });
    }
  },

  useSignup: async (
    username: string,
    email: string,
    password: string,
    confirmPassword: string,
    termsAccepted: boolean
  ) => {
    try {
      set({ isLoading: true, error: null });
      const response = await fetch("/api/v1/public/sign-up", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        credentials: "include",
        body: JSON.stringify({
          username,
          email,
          password,
          confirmPassword,
          termsAccepted,
        }),
      });
      const json = (await response.json()) as {
        ok: boolean;
        message: string;
        securityQuestionsAnswered?: boolean;
      };

      if (json.ok) {
        set({
          isAuthenticated: true,
          isSecurityQuestionsAnswered: json?.securityQuestionsAnswered,
          error: null,
        });
      } else {
        set({
          error: json.message || "Signup failed",
          isAuthenticated: false,
          user: null,
          isSecurityQuestionsAnswered: false,
        });
      }
    } catch {
      set({
        error: "An error occurred during signup",
        isAuthenticated: false,
        user: null,
        isSecurityQuestionsAnswered: false,
      });
    } finally {
      set({ isLoading: false });
    }
  },

  useSecurityQuestions: async (
    questions: { question: string; answer: string }[]
  ) => {
    try {
      set({ isLoading: true, error: null });
      const response = await fetchWithAuth(
        "/api/v1/account/security-questions",
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ questions }),
        }
      );
      const json = await response.json();
      if (json.ok) {
        set({
          isSecurityQuestionsAnswered: true,
          error: null,
        });
      } else {
        set({
          error: json.message || "An error occurred during security questions",
        });
      }
    } catch (error) {
      set({ error: "An error occurred during security questions" });
    } finally {
      set({ isLoading: false });
    }
  },

  isSessionExpiring: false,
  sessionTimeRemaining: 0,

  setSessionExpiring: (isExpiring: boolean, timeRemaining: number = 60) => {
    set({
      isSessionExpiring: isExpiring,
      sessionTimeRemaining: timeRemaining,
    });
  },

  renewSession: async () => {
    try {
      set({ isLoading: true, error: null });
      const response = await fetch("/api/v1/public/refresh-token", {
        method: "POST",
        credentials: "include",
      });

      const json = await validateResponse(response);

      if (json.ok) {
        set({
          isSessionExpiring: false,
          sessionTimeRemaining: 0,
          error: null,
        });
      } else {
        set({
          error: json.message || "Failed to renew session",
          isAuthenticated: false,
          user: null,
        });
      }
    } catch (error) {
      set({
        error: "An error occurred while renewing session",
        isAuthenticated: false,
        user: null,
      });
    } finally {
      set({ isLoading: false });
    }
  },
  displayLoginModal: false,
  setDisplayLoginModal: (display: boolean) => {
    set((state) => ({
      displayLoginModal: state.isAuthenticated ? false : display,
    }));
  },
  pagesProcessed: 0,
  setPagesProcessed: async () => {
    const response = await fetchWithAuth("/api/v1/account/pages-processed", {
      method: "GET",
    });
    const json = await response.json();

    set({ pagesProcessed: json.pages_processed });
  },
}));
