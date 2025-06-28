import { create } from "zustand";
import {
  PagePreviews,
  PageSelection,
  StatementData,
  Transaction,
} from "./ImportBankStatement.types";
import { generateId } from "@/utils/generateId";
import { devtools } from "zustand/middleware";

type State = {
  file: File | null;
  pageSelection: PageSelection | null;
  statement: StatementData | null;
  statement_copy: StatementData | null;
  error: string;
  isLoading: boolean;
  previewsLoading: boolean;
  isDrawingMode: boolean;
  selectedPageForDrawing: number | null;
  redactedPageFiles: { [pageNum: number]: File };
};

type Action = {
  setFile: (file: File | null) => void;
  setPageSelection: (pageSelection: PageSelection | null) => void;
  setPagePreviews: (pagePreviews: PagePreviews) => void;
  togglePageSelection: (pageNum: number) => void;
  updatePagePreview: (pageNum: number, previewUrl: string) => void;
  setError: (error: string) => void;
  setIsLoading: (isLoading: boolean) => void;
  setPreviewsLoading: (previewsLoading: boolean) => void;
  setIsDrawingMode: (isDrawingMode: boolean) => void;
  setSelectedPageForDrawing: (selectedPageForDrawing: number | null) => void;
  setRedactedPageFile: (pageNum: number, file: File) => void;
  submitSelectedPages: () => Promise<void>;
  handleFileChange: (file: File) => Promise<void>;
  loadPreviews: () => Promise<void>;
  adjustTransaction: (transaction: Transaction) => void;
  mergeStatement: () => void;
  resetStatementCopy: () => void;
  getUserTransactions: () => Promise<void>;
  reset: () => void;
};

const importBankStatementStore = create<State & Action>()(
  devtools(
    (set) => ({
      // State
      file: null,
      pageSelection: null,
      statement: null,
      statement_copy: null,
      error: "",
      isLoading: false,
      previewsLoading: false,
      isDrawingMode: false,
      selectedPageForDrawing: null,
      redactedPageFiles: {},

      // Actions
      setFile: (file) =>
        set({ file }, undefined, "ImportBankStatementStore/SetFile"),

      setPageSelection: (pageSelection) => {
        if (!pageSelection) return;

        set(
          (state) => {
            return {
              ...state,
              pageSelection: {
                ...state.pageSelection,
                ...pageSelection,
              },
            };
          },
          undefined,
          "ImportBankStatementStore/SetPageSelection"
        );
      },

      setPagePreviews: (pagePreviews: PagePreviews) => {
        if (!pagePreviews) return;

        set(
          (state) => {
            if (!state.pageSelection) return state;

            console.log("Setting page previews to", pagePreviews);

            return {
              ...state,
              pageSelection: {
                ...state.pageSelection,
                previews: {
                  ...state.pageSelection?.previews,
                  ...pagePreviews,
                },
              },
            };
          },
          undefined,
          "ImportBankStatementStore/SetPagePreviews"
        );
      },

      togglePageSelection: (pageNum) =>
        set(
          (state) => {
            if (!state.pageSelection) return state;

            const selectedPages = state.pageSelection.selectedPages.includes(
              pageNum
            )
              ? state.pageSelection.selectedPages.filter((p) => p !== pageNum)
              : [...state.pageSelection.selectedPages, pageNum];

            return {
              pageSelection: {
                ...state.pageSelection,
                selectedPages,
              },
            };
          },
          undefined,
          "ImportBankStatementStore/TogglePageSelection"
        ),

      updatePagePreview: (pageNum, previewUrl) =>
        set(
          (state) => {
            if (!state.pageSelection) return state;

            return {
              pageSelection: {
                ...state.pageSelection,
                previews: {
                  ...state.pageSelection.previews,
                  [pageNum]: previewUrl,
                },
              },
            };
          },
          undefined,
          "ImportBankStatementStore/UpdatePagePreview"
        ),
      setError: (error) =>
        set({ error }, undefined, "ImportBankStatementStore/SetError"),
      setIsLoading: (isLoading) =>
        set({ isLoading }, undefined, "ImportBankStatementStore/SetIsLoading"),
      setPreviewsLoading: (previewsLoading) =>
        set(
          { previewsLoading },
          undefined,
          "ImportBankStatementStore/SetPreviewsLoading"
        ),
      setIsDrawingMode: (isDrawingMode) =>
        set(
          { isDrawingMode },
          undefined,
          "ImportBankStatementStore/SetIsDrawingMode"
        ),
      setSelectedPageForDrawing: (selectedPageForDrawing) =>
        set(
          { selectedPageForDrawing },
          undefined,
          "ImportBankStatementStore/SetSelectedPageForDrawing"
        ),
      setRedactedPageFile: (pageNum, file) =>
        set(
          (state) => ({
            ...state,
            redactedPageFiles: {
              ...state.redactedPageFiles,
              [pageNum]: file,
            },
          }),
          undefined,
          "ImportBankStatementStore/SetRedactedPageFile"
        ),

      submitSelectedPages: async () => {
        const state = importBankStatementStore.getState();
        const { pageSelection, file, redactedPageFiles } = state;

        if (
          !pageSelection ||
          pageSelection.selectedPages.length === 0 ||
          !file
        ) {
          return;
        }

        set(
          { isLoading: true, error: "", statement: null, statement_copy: null },
          undefined,
          "ImportBankStatementStore/SubmitSelectedPages"
        );

        const formData = new FormData();

        // Check if any selected pages have redacted versions
        const hasRedactedPages = pageSelection.selectedPages.some(
          (pageNum) => redactedPageFiles[pageNum]
        );

        if (hasRedactedPages && pageSelection.selectedPages.length === 1) {
          // If only one page is selected and it has a redacted version, use that
          const pageNum = pageSelection.selectedPages[0];
          const redactedFile = redactedPageFiles[pageNum];
          if (redactedFile) {
            formData.append("file", redactedFile);
            formData.append("pages", "1"); // Redacted file is a single-page PDF
          } else {
            formData.append("file", file);
            formData.append("pages", pageSelection.selectedPages.join(","));
          }
        } else if (hasRedactedPages) {
          // Multiple pages with some redacted - need to merge PDFs
          // For now, fall back to original file with a warning
          console.warn(
            "Multiple pages with redactions not yet supported - using original file"
          );
          formData.append("file", file);
          formData.append("pages", pageSelection.selectedPages.join(","));
        } else {
          // No redacted pages, use original file
          formData.append("file", file);
          formData.append("pages", pageSelection.selectedPages.join(","));
        }

        try {
          const textExtractionResponse = await fetch(
            "/api/v1/pdf/extract-text-native",
            {
              method: "POST",
              body: formData,
            }
          );

          const textExtractionData = await textExtractionResponse.json();
          if (!textExtractionResponse.ok) {
            throw new Error(textExtractionData.error);
          }

          // Step 2: Format the extracted text
          const formatDataResponse = await fetch(
            "/api/v1/pdf/format-data-from-text",
            {
              method: "POST",
              headers: {
                "Content-Type": "application/json",
              },
              body: JSON.stringify({
                text: textExtractionData.text,
                pages: formData.get("pages"),
              }),
            }
          );

          const formattedData = await formatDataResponse.json();
          if (!formatDataResponse.ok) {
            throw new Error(formattedData.error);
          }

          const transactions = formattedData.transactions.map(
            (t: Transaction) => ({
              ...t,
              id: generateId("transaction-"),
            })
          );

          console.log("data", formattedData);

          set(
            {
              statement: { ...formattedData, transactions },
              statement_copy: { ...formattedData, transactions },
            },
            undefined,
            "ImportBankStatementStore/SubmitSelectedPages"
          );
        } catch (error: unknown) {
          set(
            {
              error:
                error instanceof Error ? error.message : "An error occurred",
            },
            undefined,
            "ImportBankStatementStore/SubmitSelectedPages"
          );
        } finally {
          set(
            { isLoading: false },
            undefined,
            "ImportBankStatementStore/SubmitSelectedPages"
          );
        }
      },
      handleFileChange: async (file: File) => {
        try {
          const response = await fetch("/api/v1/account/auth-check", {
            credentials: "include",
          });
          const json = (await response.json()) as {
            ok: boolean;
            data: {
              tokenExpiresIn: number;
              inactiveAt: { Valid: boolean };
            };
          };

          if (
            !json.ok ||
            json?.data?.tokenExpiresIn <= 0 ||
            json?.data?.inactiveAt?.Valid
          ) {
            set(
              {
                error: "You must be logged in to upload a file",
              },
              undefined,
              "ImportBankStatementStore/HandleFileChange"
            );
            return;
          }

          if (file?.type === "application/pdf") {
            set(
              { file, error: "" },
              undefined,
              "ImportBankStatementStore/HandleFileChange"
            );

            const formData = new FormData();
            formData.append("file", file);

            try {
              const pageCountResponse = await fetch(
                "/api/v1/pdf/page-count-native",
                {
                  method: "POST",
                  body: formData,
                }
              );

              const pageCountData = await pageCountResponse.json();
              if (!pageCountResponse.ok) throw new Error(pageCountData.error);

              set(
                {
                  pageSelection: {
                    fileId: pageCountData.fileId,
                    numPages: pageCountData.numPages,
                    selectedPages: [],
                    previews: {},
                  },
                },
                undefined,
                "ImportBankStatementStore/HandleFileChange"
              );
            } catch (err) {
              set(
                {
                  error:
                    err instanceof Error ? err.message : "An error occurred",
                  file: null,
                },
                undefined,
                "ImportBankStatementStore/HandleFileChange"
              );
            }
          } else {
            set(
              {
                error: "Please select a valid PDF file",
                file: null,
              },
              undefined,
              "ImportBankStatementStore/HandleFileChange"
            );
          }
        } catch (err) {
          set(
            {
              error:
                "Authentication check failed. Please try signing in again.",
              file: null,
            },
            undefined,
            "ImportBankStatementStore/HandleFileChange"
          );
        }
      },
      loadPreviews: async () => {
        const state = importBankStatementStore.getState();
        const { file, pageSelection } = state;
        if (!file || !pageSelection) return;

        // Clean up existing preview URLs to prevent memory leaks
        if (pageSelection.previews) {
          Object.values(pageSelection.previews).forEach((url) => {
            if (url) {
              try {
                URL.revokeObjectURL(url);
              } catch (err) {
                console.error("Failed to revoke object URL:", err);
              }
            }
          });
        }

        set(
          { previewsLoading: true },
          undefined,
          "ImportBankStatementStore/LoadPreviews"
        );

        // Reset previews to empty object
        set(
          (state) => ({
            pageSelection: state.pageSelection
              ? {
                  ...state.pageSelection,
                  previews: {},
                }
              : null,
          }),
          undefined,
          "ImportBankStatementStore/LoadPreviews"
        );

        for (let pageNum = 1; pageNum <= pageSelection.numPages; pageNum++) {
          const formData = new FormData();
          formData.append("file", file);
          formData.append("page", pageNum.toString());

          try {
            const previewResponse = await fetch(
              "/api/v1/pdf/pdf-to-image-native",
              {
                method: "POST",
                body: formData,
                headers: {
                  Accept: "application/json",
                },
              }
            );

            if (!previewResponse.ok) continue;

            const previewBlob = await previewResponse.blob();
            const previewUrl = URL.createObjectURL(previewBlob);

            set(
              (state) => ({
                pageSelection: state.pageSelection
                  ? {
                      ...state.pageSelection,
                      previews: {
                        ...state.pageSelection.previews,
                        [pageNum]: previewUrl,
                      },
                    }
                  : null,
              }),
              undefined,
              "ImportBankStatementStore/LoadPreviews"
            );
          } catch (error) {
            console.error(`Failed to load preview for page ${pageNum}:`, error);
          }
        }
        set(
          { previewsLoading: false },
          undefined,
          "ImportBankStatementStore/LoadPreviews"
        );
      },
      adjustTransaction: (transaction) => {
        set(
          (state) => {
            if (!state.statement_copy) return state;
            return {
              ...state,
              statement_copy: {
                ...state.statement_copy,
                transactions: state.statement_copy?.transactions.map((t) => {
                  if (t.id === transaction.id) {
                    return transaction;
                  }
                  return t;
                }),
              },
            };
          },
          false,
          "ImportBankStatementStore/AdjustTransaction"
        );
      },
      mergeStatement: () => {
        set(
          (state) => {
            if (!state.statement_copy) return state;
            return { ...state, statement: state.statement_copy };
          },
          false,
          "ImportBankStatementStore/MergeStatement"
        );
      },
      resetStatementCopy: () => {
        set(
          (state) => ({
            ...state,
            statement_copy: state.statement,
          }),
          false,
          "ImportBankStatementStore/ResetStatementCopy"
        );
      },
      getUserTransactions: async () => {
        const state = importBankStatementStore.getState();

        try {
          const response = await fetch("/api/v1/transactions");
          if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
          }
          const json = await response.json();

          set(
            {
              statement: {
                ...state.statement,
                transactions: json.data.transactions,
              },
              statement_copy: {
                ...state.statement_copy,
                transactions: json.data.transactions,
              },
            },
            undefined,
            "ImportBankStatementStore/GetUserTransactions"
          );
        } catch (err) {
          set(
            {
              error:
                err instanceof Error
                  ? err.message
                  : "Failed to fetch transactions",
            },
            undefined,
            "ImportBankStatementStore/GetUserTransactions"
          );
          console.error("Failed to fetch transactions:", err);
        }
      },
      reset: () => {
        const state = importBankStatementStore.getState();

        // Clean up existing preview URLs to prevent memory leaks
        if (state.pageSelection?.previews) {
          Object.values(state.pageSelection.previews).forEach((url) => {
            if (url) {
              try {
                URL.revokeObjectURL(url);
              } catch (err) {
                console.error("Failed to revoke object URL:", err);
              }
            }
          });
        }

        // Clean up redacted page files URLs if they exist
        if (state.redactedPageFiles) {
          Object.values(state.redactedPageFiles).forEach((file) => {
            if (file && typeof file === "object" && "name" in file) {
              // These are File objects, not URLs, so no cleanup needed
            }
          });
        }

        set(
          {
            file: null,
            pageSelection: null,
            statement: null,
            statement_copy: null,
            error: "",
            isLoading: false,
            previewsLoading: false,
            isDrawingMode: false,
            selectedPageForDrawing: null,
            redactedPageFiles: {},
          },
          undefined,
          "ImportBankStatementStore/Reset"
        );
      },
    }),
    {
      enabled: process.env.NODE_ENV === "development",
    }
  )
);

export default importBankStatementStore;
