import React, { useEffect } from "react";
import { DrawingData } from "../ImportBankStatement.types";
import PDFDrawingCanvas from "../../PDFDrawingCanvas";
import importBankStatementStore from "../ImportBankStatement.store";

const PdfSafetyMarker: React.FC = () => {
  const file = importBankStatementStore((state) => state.file);
  const pageSelection = importBankStatementStore(
    (state) => state.pageSelection
  );

  const setError = importBankStatementStore((state) => state.setError);
  const setPreviewsLoading = importBankStatementStore(
    (state) => state.setPreviewsLoading
  );
  const isDrawingMode = importBankStatementStore(
    (state) => state.isDrawingMode
  );
  const setIsDrawingMode = importBankStatementStore(
    (state) => state.setIsDrawingMode
  );
  const selectedPageForDrawing = importBankStatementStore(
    (state) => state.selectedPageForDrawing
  );
  const setSelectedPageForDrawing = importBankStatementStore(
    (state) => state.setSelectedPageForDrawing
  );

  const setPagePreviews = importBankStatementStore(
    (state) => state.setPagePreviews
  );

  useEffect(() => {
    if (
      !file ||
      !pageSelection ||
      Object.keys(pageSelection.previews).length > 0
    )
      return;

    const loadPreviews = async () => {
      setPreviewsLoading(true);

      for (let pageNum = 1; pageNum <= pageSelection.numPages; pageNum++) {
        const formData = new FormData();
        formData.append("file", file);
        formData.append("page", pageNum.toString());

        try {
          const previewResponse = await fetch("/api/v1/pdf/upload-pdf", {
            method: "POST",
            body: formData,
            headers: {
              Accept: "application/json",
            },
          });

          if (!previewResponse.ok) continue;

          const previewBlob = await previewResponse.blob();
          const previewUrl = URL.createObjectURL(previewBlob);

          setPagePreviews({
            [pageNum]: previewUrl,
          });
        } catch (error) {
          console.error(`Failed to load preview for page ${pageNum}:`, error);
        }
      }
      setPreviewsLoading(false);
    };

    loadPreviews();
  }, [file, pageSelection?.numPages]);

  const handleSaveDrawing = async (vectorData: DrawingData[]) => {
    if (!file || selectedPageForDrawing === null) return;

    try {
      const formData = new FormData();
      formData.append("file", file);
      formData.append("page", selectedPageForDrawing.toString());
      formData.append("drawing", JSON.stringify(vectorData));

      const response = await fetch("/api/v1/pdf/apply-drawing", {
        method: "POST",
        body: formData,
      });

      if (!response.ok) throw new Error("Failed to save drawing");

      // Update preview with the modified PDF
      const modifiedPdfBlob = await response.blob();
      const previewFormData = new FormData();
      previewFormData.append(
        "file",
        new File([modifiedPdfBlob], "temp.pdf", { type: "application/pdf" })
      );
      previewFormData.append("page", selectedPageForDrawing.toString());

      const previewResponse = await fetch("/api/v1/pdf/upload-pdf", {
        method: "POST",
        body: previewFormData,
      });

      if (!previewResponse.ok) throw new Error("Failed to update preview");

      const previewBlob = await previewResponse.blob();
      const previewUrl = URL.createObjectURL(previewBlob);

      // Revoke old preview URL if it exists
      if (pageSelection?.previews[selectedPageForDrawing]) {
        URL.revokeObjectURL(pageSelection.previews[selectedPageForDrawing]!);
      }

      // Update the preview in state
      setPagePreviews({
        [selectedPageForDrawing]: previewUrl,
      });

      setIsDrawingMode(false);
      setSelectedPageForDrawing(null);
    } catch (error) {
      console.error("Error saving drawing:", error);
      setError(
        error instanceof Error ? error.message : "Failed to save drawing"
      );
    }
  };

  if (
    !isDrawingMode ||
    selectedPageForDrawing === null ||
    selectedPageForDrawing === undefined ||
    !pageSelection?.previews[selectedPageForDrawing]
  )
    return null;

  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4">
      <PDFDrawingCanvas
        backgroundImage={pageSelection.previews[selectedPageForDrawing]}
        onSave={handleSaveDrawing}
        onClose={() => {
          setIsDrawingMode(false);
          setSelectedPageForDrawing(null);
        }}
      />
    </div>
  );
};

export default PdfSafetyMarker;
