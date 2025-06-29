# Apply Drawing Route - Python to Go Migration TODO

## Overview
This document outlines the steps needed to replace the `/apply-drawing` API route's Python implementation with a native Go equivalent. Currently, the Go server forwards requests to a Python Flask service that uses PyMuPDF for PDF manipulation.

## Current Implementation Analysis

### Python Service (`lib/pdf_service/main.py:138-210`)
- **Endpoint**: `/api/v1/internal/pdf/apply-drawing`
- **Functionality**: Applies redaction annotations to PDF pages
- **Libraries**: PyMuPDF (fitz), Flask
- **Input**: 
  - PDF file (multipart form)
  - Page number (form field)
  - Drawing data JSON (form field)
- **Output**: Modified PDF with redactions applied

### Go Proxy (`pkg/api/pdf_handler.go:759-840`)
- **Endpoint**: `/api/v1/pdf/apply-drawing`
- **Functionality**: Forwards requests to Python service
- **Current Status**: Proxy implementation that needs replacement

### Drawing Data Structure
```typescript
interface DrawingData {
  type: "rect";
  left: number;
  top: number;
  width: number;
  height: number;
  color: string;
  opacity: number;
}
```

## Migration Tasks

### 1. Create Native Go Implementation
- [ ] Create new file: `pkg/api/apply_drawing_native.go`
- [ ] Implement `ApplyDrawingNative` function using `github.com/gen2brain/go-fitz`
- [ ] Follow existing patterns from `pdf_to_image_native.go`

### 2. Input Validation & Processing
- [ ] Validate uploaded file is a PDF
- [ ] Check file size limits (MAX_FILE_SIZE equivalent)
- [ ] Parse and validate page number parameter
- [ ] Parse and validate drawing data JSON
- [ ] Implement proper error handling with consistent response format

### 3. PDF Manipulation Logic
- [ ] Open PDF from memory using go-fitz
- [ ] Create new PDF document
- [ ] Copy all pages from original to new document
- [ ] Get target page for modification
- [ ] Parse drawing data rectangles
- [ ] Apply redaction annotations to specified rectangles
- [ ] Set redaction fill color to black (matching Python implementation)
- [ ] Apply redactions permanently to remove underlying content

### 4. Response Handling
- [ ] Save modified PDF with high quality settings
- [ ] Return PDF as downloadable file with proper headers
- [ ] Set appropriate MIME type (`application/pdf`)
- [ ] Set download filename (e.g., `page_{page_num}.pdf`)

### 5. Route Integration
- [ ] Add new route to main.go: `pdfRoutes.POST("/apply-drawing-native", api.ApplyDrawingNative)`
- [ ] Test new native implementation thoroughly
- [ ] Update frontend to use new endpoint (optional for testing)

### 6. Error Handling & Logging
- [ ] Implement comprehensive error handling
- [ ] Add appropriate logging using existing logger patterns
- [ ] Handle edge cases:
  - Invalid PDF files
  - Page numbers out of range
  - Malformed drawing data
  - Memory allocation issues

### 7. Testing & Validation
- [ ] Create unit tests for the new function
- [ ] Test with various PDF files and drawing configurations
- [ ] Verify output matches Python implementation behavior
- [ ] Performance testing compared to Python service

### 8. Documentation & Cleanup
- [ ] Update API documentation
- [ ] Add code comments explaining redaction logic
- [ ] Document any differences from Python implementation

### 9. Migration Strategy
- [ ] Deploy native implementation alongside existing proxy
- [ ] Gradually migrate frontend to use native endpoint
- [ ] Monitor performance and error rates
- [ ] Remove Python service dependency once migration is complete

## Technical Notes

### Go-Fitz Library Usage
The project already includes `github.com/gen2brain/go-fitz` which provides Go bindings for MuPDF (same library used by Python PyMuPDF). Key functions needed:
- `fitz.NewFromMemory()` - Open PDF from bytes
- `doc.NumPage()` - Get page count
- Document manipulation for redactions

### Drawing Data Processing
The frontend sends drawing data as JSON with rectangle coordinates. Each rectangle needs to be converted to a redaction annotation that permanently removes underlying content.

### File Size Limits
Maintain existing file size validation (MAX_FILE_SIZE from Python config).

### Response Format
Ensure the Go implementation returns the exact same response format as the Python service to maintain frontend compatibility.

## Dependencies
- ✅ `github.com/gen2brain/go-fitz` (already in go.mod)
- ✅ `github.com/gin-gonic/gin` (already in go.mod)
- ✅ Standard library packages (encoding/json, io, bytes, etc.)

## Success Criteria
- [ ] Native Go implementation produces identical PDF output to Python service
- [ ] All existing frontend functionality works without changes
- [ ] Performance is equal or better than Python implementation
- [ ] Error handling is comprehensive and user-friendly
- [ ] Code follows existing Go patterns and conventions in the project