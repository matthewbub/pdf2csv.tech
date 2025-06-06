import React, { useEffect } from "react";
import importBankStatementStore from "./ImportBankStatement.store";

const ImportBankStatementLifecycle: React.FC<{ children: React.ReactNode }> = ({
  children,
}) => {
  const file = importBankStatementStore((state) => state.file);
  const pageSelection = importBankStatementStore(
    (state) => state.pageSelection
  );

  const loadPreviews = importBankStatementStore((state) => state.loadPreviews);

  useEffect(() => {
    if (
      !file ||
      !pageSelection ||
      Object.keys(pageSelection.previews).length > 0
    ) {
      return;
    }

    loadPreviews();

    return () => {
      if (pageSelection?.previews) {
        Object.values(pageSelection.previews).forEach((url) => {
          if (url) {
            try {
              URL.revokeObjectURL(url);
            } catch (err) {
              console.error("Failed to revoke object URL:", err);
              // Continue cleanup even if one URL fails
            }
          }
        });
      }
    };
  }, [file, pageSelection?.numPages]);

  return <>{children}</>;
};

export default ImportBankStatementLifecycle;
