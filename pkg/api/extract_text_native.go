package api

import (
	"bytes"
	"net/http"
	"strconv"
	"strings"

	"github.com/gen2brain/go-fitz"
	"github.com/gin-gonic/gin"
)

func ExtractPDFTextNative(c *gin.Context) {
	file, err := c.FormFile("file")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"error":   "No file provided",
		})
		return
	}

	pagesToExtract := c.PostForm("pages")
	pageStrs := strings.Split(pagesToExtract, ",")
	var pages []int
	for _, pStr := range pageStrs {
		pStr = strings.TrimSpace(pStr)
		if pStr == "" {
			continue
		}
		p, err := strconv.Atoi(pStr)
		if err != nil || p <= 0 {
			c.JSON(http.StatusBadRequest, gin.H{
				"success": false,
				"error":   "Invalid page numbers",
			})
			return
		}
		pages = append(pages, p)
	}

	if len(pages) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"error":   "No valid page numbers provided",
		})
		return
	}

	src, err := file.Open()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "Failed to open file"})
		return
	}
	defer src.Close()

	var buf bytes.Buffer
	_, err = buf.ReadFrom(src)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "Failed to read file into buffer"})
		return
	}

	doc, err := fitz.NewFromMemory(buf.Bytes())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "Failed to open PDF from memory"})
		return
	}
	defer doc.Close()

	totalPages := doc.NumPage()
	for _, p := range pages {
		if p > totalPages {
			c.JSON(http.StatusBadRequest, gin.H{
				"success": false,
				"error":   "Page number exceeds document length (" + strconv.Itoa(totalPages) + " pages)",
			})
			return
		}
	}

	sensitivePatterns := []string{"TEST"}
	var textParts []string
	for _, pageNum := range pages {
		text, err := doc.Text(pageNum - 1) // go-fitz is 0-indexed
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"success": false,
				"error":   "Failed to extract text from page " + strconv.Itoa(pageNum),
			})
			return
		}

		textLower := strings.ToLower(text)
		var matchedPatterns []string
		for _, pattern := range sensitivePatterns {
			if strings.Contains(textLower, strings.ToLower(pattern)) {
				matchedPatterns = append(matchedPatterns, pattern)
			}
		}

		if len(matchedPatterns) > 0 {
			c.JSON(http.StatusBadRequest, gin.H{
				"success": false,
				"data": gin.H{
					"patterns_matched": matchedPatterns,
				},
				"error": "Document contains sensitive information and cannot be processed",
			})
			return
		}

		textParts = append(textParts, text)
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"text":    strings.Join(textParts, "\n"),
	})
}
