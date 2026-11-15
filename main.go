package main

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/elazarl/goproxy"
	"github.com/gen2brain/beeep"
)

// Giải nén nếu server trả về Content-Encoding: gzip
func readBody(resp *http.Response) ([]byte, error) {
	rawBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	// Khôi phục lại stream để trình duyệt nhận dữ liệu bình thường
	resp.Body = io.NopCloser(bytes.NewBuffer(rawBytes))

	if strings.EqualFold(resp.Header.Get("Content-Encoding"), "gzip") {
		reader, err := gzip.NewReader(bytes.NewBuffer(rawBytes))
		if err == nil {
			defer reader.Close()
			if decompressed, err := io.ReadAll(reader); err == nil {
				return decompressed, nil
			}
		}
	}
	return rawBytes, nil
}

// Chuẩn hóa JSON để so sánh chính xác, không bị lệch do format
func formatJSON(raw []byte) []byte {
	var out bytes.Buffer
	if err := json.Indent(&out, raw, "", "  "); err == nil {
		return out.Bytes()
	}
	return raw
}

func main() {
	// 1. Xuất chứng chỉ CA ra file ca.crt nếu chưa có (dùng để cài vào Chrome 1 lần duy nhất)
	if _, err := os.Stat("ca.crt"); os.IsNotExist(err) {
		os.WriteFile("ca.crt", goproxy.CA_CERT, 0644)
		fmt.Println("🔑 Đã tạo file 'ca.crt'. Hãy import file này vào trình duyệt để bắt HTTPS!")
	}

	// 2. Đọc file cấu hình rules.json
	ruleBytes, err := os.ReadFile("rules.json")
	if err != nil {
		log.Fatal("❌ Lỗi: Không tìm thấy file rules.json cùng thư mục! ", err)
	}
	var rules map[string]string
	if err := json.Unmarshal(ruleBytes, &rules); err != nil {
		log.Fatal("❌ Lỗi cú pháp trong file rules.json: ", err)
	}

	proxy := goproxy.NewProxyHttpServer()
	proxy.Verbose = false
	// Bật giải mã HTTPS
	proxy.OnRequest().HandleConnect(goproxy.AlwaysMitm)

	// 3. Lắng nghe và xử lý Response
	proxy.OnResponse().DoFunc(func(resp *http.Response, ctx *goproxy.ProxyCtx) *http.Response {
		if resp == nil || resp.Body == nil || ctx.Req == nil {
			return resp
		}

		url := ctx.Req.URL.String()
		for pattern, targetPath := range rules {
			if strings.Contains(url, pattern) {
				bodyBytes, err := readBody(resp)
				if err != nil {
					continue
				}

				formatted := formatJSON(bodyBytes)
				os.MkdirAll(filepath.Dir(targetPath), os.ModePerm)

				if _, err := os.Stat(targetPath); os.IsNotExist(err) {
					// LẦN ĐẦU TIÊN: Lưu làm file Origin
					os.WriteFile(targetPath, formatted, 0644)
					fmt.Printf("[ORIGIN] Đã ghi lần đầu: %s -> %s\n", pattern, targetPath)
					beeep.Notify("📌 API Origin Saved", "Đã ghi bản gốc: "+filepath.Base(targetPath), "")
				} else {
					// LẦN THỨ 2 TRỞ ĐI: So sánh với file Origin
					originBytes, _ := os.ReadFile(targetPath)
					if !bytes.Equal(originBytes, formatted) {
						ext := filepath.Ext(targetPath)
						diffPath := strings.TrimSuffix(targetPath, ext) + "_diff" + ext
						os.WriteFile(diffPath, formatted, 0644)

						fmt.Printf("[DIFF!] Phát hiện thay đổi: %s -> Đã lưu %s\n", pattern, diffPath)
						beeep.Notify("⚠️ API Diff Detected!", "API thay đổi: "+pattern+"\nXem file: "+filepath.Base(diffPath), "")
					} else {
						fmt.Printf("[OK] Không có thay đổi: %s\n", pattern)
					}
				}
			}
		}
		return resp
	})

	port := ":8888"
	fmt.Printf("🚀 API Watcher đang chạy tại 127.0.0.1%s (Đang theo dõi %d API)...\n", port, len(rules))
	log.Fatal(http.ListenAndServe(port, proxy))
}