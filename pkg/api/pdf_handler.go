package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"mime/multipart"
	"net/textproto"

	"bus.zcauldron.com/pkg/utils"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

type PythonResponseData struct {
	PatternsMatched []string `json:"patterns_matched"`
}

type PythonResponse struct {
	Success bool               `json:"success"`
	Text    string             `json:"text"`
	Data    PythonResponseData `json:"data"`
	Error   string             `json:"error"`
}

type Transaction struct {
	Date        string  `json:"date"`
	Description string  `json:"description"`
	Amount      float64 `json:"amount"`
	Type        string  `json:"type"`
}

type StatementData struct {
	Transactions []Transaction `json:"transactions"`
}

type PDFPageCount struct {
	NumPages int    `json:"numPages"`
	FileID   string `json:"fileId"`
}

func ExtractPDFText(c *gin.Context) {
	logger := utils.GetLogger()

	tokenString, err := c.Cookie("jwt")
	if err != nil || tokenString == "" {
		logger.Printf("Unauthorized access attempt: missing or empty JWT")
		c.JSON(401, gin.H{"error": "Unauthorized"})
		return
	}

	userID, _, err := utils.VerifyJWT(tokenString)
	if err != nil {
		logger.Printf("JWT verification failed: %v", err)
		c.JSON(401, gin.H{"error": "Unauthorized"})
		return
	}

	file, err := c.FormFile("file")
	if err != nil {
		logger.Printf("No file uploaded: %v", err)
		c.JSON(400, gin.H{"error": "No file uploaded"})
		return
	}
	pagesStr := c.PostForm("pages")

	// Parse and validate pages
	var pages []int
	for _, p := range strings.Split(pagesStr, ",") {
		page, err := strconv.Atoi(strings.TrimSpace(p))
		if err != nil {
			logger.Printf("Invalid page number: %v", err)
			c.JSON(400, gin.H{"error": "Invalid page number"})
			return
		}
		pages = append(pages, page)
	}

	// Create a new multipart form
	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)

	// Create the form file and capture the file part
	filePart, err := writer.CreateFormFile("file", file.Filename)
	if err != nil {
		logger.Printf("Failed to create form file: %v", err)
		c.JSON(500, gin.H{"error": "Failed to create form file"})
		return
	}

	// Open the uploaded file
	src, err := file.Open()
	if err != nil {
		logger.Printf("Failed to open uploaded file: %v", err)
		c.JSON(500, gin.H{"error": "Failed to open uploaded file"})
		return
	}
	defer src.Close()

	// Copy the file content to the form part
	if _, err = io.Copy(filePart, src); err != nil {
		logger.Printf("Failed to copy file content: %v", err)
		c.JSON(500, gin.H{"error": "Failed to copy file content"})
		return
	}

	// Add all pages in a single request
	pagesStr = strings.Join(strings.Fields(fmt.Sprint(pages)), ",")
	pagesStr = strings.Trim(pagesStr, "[]")
	if err := writer.WriteField("pages", pagesStr); err != nil {
		logger.Printf("Failed to write pages field: %v", err)
		c.JSON(500, gin.H{"error": "Failed to write pages field"})
		return
	}
	writer.Close()

	pdfServiceURL := utils.GetPDFServiceURL()
	req, err := http.NewRequest("POST", pdfServiceURL+"/api/v1/internal/pdf/extract-text", body)
	if err != nil {
		logger.Printf("Failed to create request: %v", err)
		c.JSON(500, gin.H{"error": "Failed to create request"})
		return
	}
	req.Header.Set("Content-Type", writer.FormDataContentType())

	// Send request
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		logger.Printf("Failed to process PDF: %v", err)
		c.JSON(500, gin.H{"error": "Failed to process PDF: " + err.Error()})
		return
	}
	defer resp.Body.Close()

	// Parse the response
	var pythonResp PythonResponse
	if err := json.NewDecoder(resp.Body).Decode(&pythonResp); err != nil {
		logger.Printf("Failed to parse Python response: %v", err)
		c.JSON(500, gin.H{"error": "Failed to parse Python response"})
		return
	}

	if !pythonResp.Success {
		logger.Printf("Python service error: %s sensitive words found in document %v", pythonResp.Error, pythonResp.Data.PatternsMatched)
		c.JSON(400, gin.H{"error": pythonResp.Error})
		return
	}

	extractedText := pythonResp.Text

	// Define the JSON schema for the response
	jsonSchema := map[string]interface{}{
		"type": "object",
		"properties": map[string]interface{}{
			"transactions": map[string]interface{}{
				"type": "array",
				"items": map[string]interface{}{
					"type": "object",
					"properties": map[string]interface{}{
						"date":        map[string]interface{}{"type": "string"},
						"description": map[string]interface{}{"type": "string"},
						"amount":      map[string]interface{}{"type": "number"},
						"type": map[string]interface{}{
							"type": "string",
							"enum": []string{"credit", "debit"},
						},
					},
					"required":             []string{"date", "description", "amount", "type"},
					"additionalProperties": false,
				},
			},
		},
		"required":             []string{"transactions"},
		"additionalProperties": false,
	}
	// Prepare OpenAI request with the extracted text
	payload := map[string]interface{}{
		"model": "gpt-4o",
		"messages": []map[string]interface{}{
			{
				"role": "user",
				"content": fmt.Sprintf(
					"Please extract the following information from this bank statement text: "+
						"account number, bank name, statement date, and all transactions. "+
						"For each transaction:\n"+
						"1. Convert all currency amounts to positive numbers with exactly 2 decimal places (e.g., '$14.99' or '-$14.99' should become 14.99, '$0.3' should become 0.30)\n"+
						"2. Mark the transaction type as 'debit' for expenses/withdrawals and 'credit' for deposits/incoming funds\n"+
						"Format the response according to the schema. Here's the text:\n\n%s",
					extractedText,
				),
			},
		},
		"temperature": 0.7,
		"max_tokens":  16384,
		"response_format": map[string]interface{}{
			"type": "json_schema",
			"json_schema": map[string]interface{}{
				"name":   "receipt_response",
				"schema": jsonSchema,
				"strict": true,
			},
		},
	}

	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		logger.Printf("Failed to marshal payload: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to marshal payload"})
		return
	}

	// Send the request to OpenAI API
	req, err = http.NewRequest("POST", "https://api.openai.com/v1/chat/completions", bytes.NewBuffer(payloadBytes))
	if err != nil {
		logger.Printf("Failed to create request: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create request"})
		return
	}

	req.Header.Set("Content-Type", "application/json")
	apiKey := os.Getenv("OPENAI_API_KEY")
	if apiKey == "" {
		logger.Printf("OpenAI API key is not set")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "OpenAI API key is not set"})
		return
	}
	req.Header.Set("Authorization", "Bearer "+apiKey)

	resp, err = client.Do(req)
	if err != nil {
		logger.Printf("Failed to send request: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to send request"})
		return
	}
	defer resp.Body.Close()

	// Read the response
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		logger.Printf("Failed to read response: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to read response"})
		return
	}

	// Unmarshal the OpenAI API response
	var openAIResp struct {
		Model string `json:"model"`
		Usage struct {
			PromptTokens     int `json:"prompt_tokens"`
			CompletionTokens int `json:"completion_tokens"`
			TotalTokens      int `json:"total_tokens"`
		} `json:"usage"`
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}

	if err := json.Unmarshal(respBody, &openAIResp); err != nil {
		logger.Printf("Failed to parse OpenAI response: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to parse OpenAI response"})
		return
	}

	var statement StatementData
	if err := json.Unmarshal([]byte(openAIResp.Choices[0].Message.Content), &statement); err != nil {
		logger.Printf("Failed to parse statement data: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to parse statement data"})
		return
	}

	// Track the number of pages processed
	pagesProcessed := len(pages)

	// Insert into pdf_processing table
	db := utils.GetDB()
	_, err = db.Exec("INSERT INTO pdf_processing (id, user_id, pages_processed) VALUES (?, ?, ?)",
		uuid.New().String(), userID, pagesProcessed)
	if err != nil {
		logger.Printf("Failed to record PDF processing: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to record PDF processing"})
		return
	}

	logger.Printf("Successfully processed PDF for user %s with %d pages", userID, pagesProcessed)
	c.JSON(200, statement)
}

func GetPDFPageCount(c *gin.Context) {
	logger := utils.GetLogger()

	file, err := c.FormFile("file")
	if err != nil {
		logger.Printf("No file uploaded: %v", err)
		c.JSON(400, gin.H{"error": "No file uploaded"})
		return
	}

	// Create a new multipart form
	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)

	// Create the form file and capture the file part
	filePart, err := writer.CreateFormFile("file", file.Filename)
	if err != nil {
		logger.Printf("Failed to create form file: %v", err)
		c.JSON(500, gin.H{"error": "Failed to create form file"})
		return
	}

	// Open the uploaded file
	src, err := file.Open()
	if err != nil {
		logger.Printf("Failed to open uploaded file: %v", err)
		c.JSON(500, gin.H{"error": "Failed to open uploaded file"})
		return
	}
	defer src.Close()

	// Copy the file content to the form part
	if _, err = io.Copy(filePart, src); err != nil {
		logger.Printf("Failed to copy file content: %v", err)
		c.JSON(500, gin.H{"error": "Failed to copy file content"})
		return
	}
	writer.Close()

	logger.Printf("Service URL: %s", utils.GetPDFServiceURL())
	pdfServiceURL := utils.GetPDFServiceURL()
	req, err := http.NewRequest("POST", pdfServiceURL+"/api/v1/internal/pdf/page-count", body)

	logger.Printf("Service Request Sent: %s", req.URL.String())
	if err != nil {
		logger.Printf("Failed to create request: %v", err)
		c.JSON(500, gin.H{"error": "Failed to create request"})
		return
	}
	req.Header.Set("Content-Type", writer.FormDataContentType())

	// Send request
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		logger.Printf("Failed to send request: %v", err)
		c.JSON(500, gin.H{"error": "Failed to process PDF: " + err.Error()})
		return
	}
	defer resp.Body.Close()

	// Read and parse response
	var pythonResp struct {
		NumPages int    `json:"numPages,omitempty"`
		Error    string `json:"error,omitempty"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&pythonResp); err != nil {
		logger.Printf("Failed to parse response: %v", err)
		c.JSON(500, gin.H{"error": "Failed to parse response"})
		return
	}

	if pythonResp.Error != "" {
		logger.Printf("Python service error: %s", pythonResp.Error)
		c.JSON(500, gin.H{"error": pythonResp.Error})
		return
	}

	// Generate a unique ID for this file
	fileID := uuid.New().String()
	logger.Printf("Successfully counted pages for file %s: %d pages", fileID, pythonResp.NumPages)
	c.JSON(200, PDFPageCount{
		NumPages: pythonResp.NumPages,
		FileID:   fileID,
	})
}

func SaveStatement(c *gin.Context) {
	logger := utils.GetLogger()

	tokenString, err := c.Cookie("jwt")
	if err != nil || tokenString == "" {
		logger.Printf("Unauthorized access attempt: missing or empty JWT")
		c.JSON(401, gin.H{"error": "Unauthorized"})
		return
	}

	userID, _, err := utils.VerifyJWT(tokenString)
	if err != nil {
		logger.Printf("JWT verification failed: %v", err)
		c.JSON(401, gin.H{"error": "Unauthorized"})
		return
	}

	// Dump JSON body to file
	body, err := io.ReadAll(c.Request.Body)
	if err != nil {
		logger.Printf("Failed to read request body: %v", err)
		c.JSON(500, gin.H{"error": "Failed to read request body"})
		return
	}

	type Statement struct {
		Transactions []Transaction `json:"transactions"`
	}

	var statement Statement
	err = json.Unmarshal(body, &statement)

	if err != nil {
		logger.Printf("Failed to parse statement data: %v", err)
		c.JSON(500, gin.H{"error": "Failed to parse statement data"})
		return
	}

	db := utils.GetDB()
	tx, err := db.Begin()

	if err != nil {
		logger.Printf("Failed to start transaction: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to start transaction"})
		return
	}

	defer tx.Rollback()

	stmt, err := tx.Prepare("INSERT INTO transactions (id, user_id, date, description, amount, type) VALUES (?, ?, ?, ?, ?, ?)")

	if err != nil {
		logger.Printf("Failed to prepare statement: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to prepare statement"})
		return
	}

	defer stmt.Close()

	// Insert each transaction
	for _, t := range statement.Transactions {
		// Parse date string to timestamp
		date, err := parseDate(t.Date)
		if err != nil {
			logger.Printf("Invalid date format: %v", err)
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid date format"})
			return
		}

		_, err = stmt.Exec(
			uuid.New().String(),
			userID,
			date,
			t.Description,
			t.Amount,
			t.Type,
		)
		if err != nil {
			logger.Printf("Failed to save transaction: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to save transaction"})
			return
		}
	}

	if err := tx.Commit(); err != nil {
		logger.Printf("Failed to commit transaction: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to commit transaction"})
		return
	}

	logger.Printf("Successfully saved %d transactions for user %s", len(statement.Transactions), userID)
	c.JSON(http.StatusOK, gin.H{
		"message": fmt.Sprintf("Successfully saved %d transactions", len(statement.Transactions)),
	})
}

func parseDate(dateStr string) (time.Time, error) {
	// Try parsing with different layouts
	layouts := []string{
		"1/2/2006",   // for single digit month/day
		"01/02/2006", // for double digit month/day
	}

	var parseErr error
	for _, layout := range layouts {
		t, err := time.Parse(layout, dateStr)
		if err == nil {
			return t, nil
		}
		parseErr = err
	}
	return time.Time{}, parseErr
}

func PDFToImage(c *gin.Context) {
	logger := utils.GetLogger()

	file, err := c.FormFile("file")
	if err != nil {
		logger.Printf("No file uploaded: %v", err)
		c.JSON(400, gin.H{"error": "No file uploaded"})
		return
	}
	// Create a new multipart form
	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)

	// Create the form file with proper headers
	h := make(textproto.MIMEHeader)
	h.Set("Content-Disposition", fmt.Sprintf(`form-data; name="%s"; filename="%s"`, "file", file.Filename))
	h.Set("Content-Type", "application/pdf")

	filePart, err := writer.CreatePart(h)
	if err != nil {
		logger.Printf("Failed to create form part: %v", err)
		c.JSON(500, gin.H{"error": "Failed to create form part"})
		return
	}

	// Open the uploaded file
	src, err := file.Open()
	if err != nil {
		logger.Printf("Failed to open uploaded file: %v", err)
		c.JSON(500, gin.H{"error": "Failed to open uploaded file"})
		return
	}
	defer src.Close()

	// Copy the file content to the form part
	if _, err = io.Copy(filePart, src); err != nil {
		logger.Printf("Failed to copy file content: %v", err)
		c.JSON(500, gin.H{"error": "Failed to copy file content"})
		return
	}

	// Add the page number from the form
	pageNum := c.PostForm("page")
	if pageNum != "" {
		if err := writer.WriteField("page", pageNum); err != nil {
			logger.Printf("Failed to write page field: %v", err)
			c.JSON(500, gin.H{"error": "Failed to process request"})
			return
		}
	}

	// Important: Close the writer before sending
	if err := writer.Close(); err != nil {
		logger.Printf("Failed to close writer: %v", err)
		c.JSON(500, gin.H{"error": "Failed to process request"})
		return
	}

	// Forward request to PDF service
	pdfServiceURL := utils.GetPDFServiceURL()
	req, err := http.NewRequest("POST", pdfServiceURL+"/api/v1/internal/pdf/pdf-to-image", body)
	if err != nil {
		logger.Printf("Failed to create request: %v", err)
		c.JSON(500, gin.H{"error": "Failed to create request"})
		return
	}

	// Set the content type with the boundary
	req.Header.Set("Content-Type", writer.FormDataContentType())

	// Send request
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		logger.Printf("Failed to send request: %v", err)
		c.JSON(500, gin.H{"error": "Failed to process PDF: " + err.Error()})
		return
	}
	defer resp.Body.Close()

	// Copy the response headers and body to the client
	for name, values := range resp.Header {
		for _, value := range values {
			c.Header(name, value)
		}
	}
	c.Status(resp.StatusCode)
	io.Copy(c.Writer, resp.Body)
}

func ApplyDrawing(c *gin.Context) {
	logger := utils.GetLogger()

	file, err := c.FormFile("file")
	if err != nil {
		logger.Printf("No file uploaded: %v", err)
		c.JSON(400, gin.H{"error": "No file uploaded"})
		return
	}

	// Check if the file is a PDF
	if !strings.HasSuffix(file.Filename, ".pdf") {
		logger.Printf("Uploaded file is not a PDF: %s", file.Filename)
		c.JSON(400, gin.H{"error": "Uploaded file is not a PDF"})
		return
	}

	// Create a new multipart form
	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)

	// Create the form file and capture the file part
	filePart, err := writer.CreateFormFile("file", file.Filename)
	if err != nil {
		logger.Printf("Failed to create form file: %v", err)
		c.JSON(500, gin.H{"error": "Failed to create form file"})
		return
	}

	// Open the uploaded file
	src, err := file.Open()
	if err != nil {
		logger.Printf("Failed to open uploaded file: %v", err)
		c.JSON(500, gin.H{"error": "Failed to open uploaded file"})
		return
	}
	defer src.Close()

	// Copy the file content to the form part
	if _, err = io.Copy(filePart, src); err != nil {
		logger.Printf("Failed to copy file content: %v", err)
		c.JSON(500, gin.H{"error": "Failed to copy file content"})
		return
	}

	// Copy all form fields to the new request
	for key, values := range c.Request.PostForm {
		for _, value := range values {
			writer.WriteField(key, value)
		}
	}
	writer.Close()

	// Forward request to PDF service
	pdfServiceURL := utils.GetPDFServiceURL()
	req, err := http.NewRequest("POST", pdfServiceURL+"/api/v1/internal/pdf/apply-drawing", body)
	if err != nil {
		logger.Printf("Failed to create request: %v", err)
		c.JSON(500, gin.H{"error": "Failed to create request"})
		return
	}
	req.Header.Set("Content-Type", writer.FormDataContentType())

	// Send request
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		logger.Printf("Failed to process PDF: %v", err)
		c.JSON(500, gin.H{"error": "Failed to process PDF: " + err.Error()})
		return
	}
	defer resp.Body.Close()

	// Copy the response headers and body directly to the client
	for name, values := range resp.Header {
		for _, value := range values {
			c.Header(name, value)
		}
	}
	c.Status(resp.StatusCode)
	io.Copy(c.Writer, resp.Body)
}
