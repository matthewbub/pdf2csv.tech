package api

import (
	"bytes"
	"image/png"
	"net/http"
	"strconv"

	"github.com/gen2brain/go-fitz"
	"github.com/gin-gonic/gin"
)

func PDFToImageNative(c *gin.Context) {
	file, err := c.FormFile("file")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "No file provided"})
		return
	}

	pageStr := c.PostForm("page")
	if pageStr == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Page number is required"})
		return
	}

	page_num, err := strconv.Atoi(pageStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid page number"})
		return
	}

	src, err := file.Open()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to open file"})
		return
	}
	defer src.Close()

	var buf bytes.Buffer
	_, err = buf.ReadFrom(src)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to read file into buffer"})
		return
	}

	doc, err := fitz.NewFromMemory(buf.Bytes())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to open PDF from memory"})
		return
	}
	defer doc.Close()

	if page_num > doc.NumPage() || page_num < 1 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Page number out of range"})
		return
	}

	// 0-indexed
	img, err := doc.Image(page_num - 1)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to convert page to image"})
		return
	}

	imgBuf := new(bytes.Buffer)
	err = png.Encode(imgBuf, img)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to encode image to PNG"})
		return
	}

	c.Data(http.StatusOK, "image/png", imgBuf.Bytes())
}
