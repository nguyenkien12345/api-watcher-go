package main

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/elazarl/goproxy"
	"github.com/gen2brain/beeep"
)

type Config struct {
	Addr          string 		// Cờ CLI: -addr 			=> Giá trị mặc định: 127.0.0.1:8888 	=> Ý nghĩa: Địa chỉ proxy lắng nghe. Bạn cấu hình trình duyệt dùng proxy tại địa chỉ này
	RulesPath     string 		// Cờ CLI: -rules 			=> Giá trị mặc định: rules.json 		=> Ý nghĩa: File khai báo những API cần theo dõi
	InlineRules   string 		// Cờ CLI: -watch 			=> Giá trị mặc định: "" 				=> Ý nghĩa: Khai báo rule thẳng trên dòng lệnh, không cần file
	OutputDir     string 		// Cờ CLI: -out-dir 		=> Giá trị mặc định: ./output 			=> Ý nghĩa: Thư mục lưu file JSON nếu rule không chỉ định đường dẫn
	CAFile        string 		// Cờ CLI: -ca-file 		=> Giá trị mặc định: ca.crt 			=> Ý nghĩa: Chứng chỉ để proxy giải mã được HTTPS. Phải import vào máy thì mới đọc được nội dung các trang https
	IgnoreKeys    []string 		// Cờ CLI: -ignore-keys 	=> Giá trị mặc định: rỗng 				=> Ý nghĩa: Các key luôn thay đổi (timestamp, requestId...) cần bỏ qua khi so sánh, nếu không thì lần nào cũng báo diff
	MaxBodyBytes  int64 		// Cờ CLI: -max-body-mb 	=> Giá trị mặc định: 10 MB 				=> Ý nghĩa: Response lớn hơn mức này thì bỏ qua để không tốn RAM
	ToastCooldown time.Duration // Cờ CLI: -toast-cooldown 	=> Giá trị mặc định: 3s 				=> Ý nghĩa: Một API thì tối đa 3 giây mới hiện thông báo một lần, chống spam
	StripCacheHeaders bool 		// Cờ CLI: -strip-cache 	=> Giá trị mặc định: true 				=> Ý nghĩa: Xoá header cache khỏi request để server luôn trả dữ liệu thật, không trả 304 Not Modified rỗng
}

type Rule struct {
	Pattern    string				 // chuỗi để so khớp URL, ví dụ "/api/orders"
	OutputPath string				 // file lưu bản gốc
	Methods    map[string]bool       // các HTTP method được theo dõi
	IgnoreKeys map[string]bool       // các key JSON bỏ qua khi so sánh
}

type RuleConfigJSON struct {
	Output     string   `json:"output"`
	Methods    []string `json:"methods"`
	IgnoreKeys []string `json:"ignore_keys"`
}

// + Watcher quản lý vòng đời quy tắc, đồng bộ hóa file I/O và chống spam thông báo.
// + Quy ước đặt khoá trong Go:
// 		- Để ý thứ tự các field: mỗi khoá đặt ngay phía trên những field mà nó bảo vệ
// + Hai điều cần biết về khoá trong struct:
// 		- Zero value dùng được ngay: sync.Mutex, sync.RWMutex, sync.Map không cần khởi tạo, vừa khai báo xong là gọi Lock() được
// 		- Struct chứa khoá thì không được copy: Copy một Watcher thì khoá cũng bị copy theo. Hai bản sẽ khoá hai thứ khác nhau, coi như không khoá gì cả. Vì thế Watcher luôn được truyền đi bằng con trỏ (*Watcher). Lệnh go vet sẽ cảnh báo nếu bạn lỡ copy

// + Cách phân biệt sync.RWMutex và sync.Mutex
// - Cả hai đều là khoá: dùng để bắt các goroutine xếp hàng khi đụng vào cùng một dữ liệu. Khác nhau ở chỗ ai được vào cùng lúc

// ===== sync.Mutex =====
// - Cách khoá: Lock() / Unlock()
// - Số người vào cùng lúc: Đúng 1 người, bất kể đọc hay ghi
// ====================

// ===== sync.RWMutex =====
// - Cách khoá: 
// 		- Khoá ghi: Lock() / Unlock()
// 		- Khoá đọc: RLock() / RUnlock()
// - Số người vào cùng lúc: Nhiều người đọc cùng lúc, hoặc đúng 1 người ghi
// ====================

// ===== Ví dụ dễ hình dung về sync.Mutex và sync.RWMutex: bảng thông báo ở sảnh ===== 
// - Mutex: bảng thông báo nằm trong phòng chỉ vừa 1 người. Đọc hay dán đều phải xếp hàng vào từng người một. Có 100 người chỉ muốn đọc cũng phải đứng chờ nhau.

// - RWMutex: bảng thông báo nằm ở sảnh rộng. 100 người đứng đọc cùng lúc thoải mái. Nhưng khi có người cần dán thông báo mới, họ hô "tạm dừng": mọi người đọc xong thì lùi ra, người đó dán một mình, dán xong thì mọi người lại đọc tiếp.
// ==========

// ===== Luật của RWMutex =====
// mu.RLock()    // xin quyền đọc
// mu.RUnlock()  // trả quyền đọc

// mu.Lock()     // xin quyền ghi
// mu.Unlock()   // trả quyền ghi

// - Nhiều RLock() cùng lúc: được
// - Lock() đang giữ: mọi RLock() và Lock() khác phải chờ
// - RLock() đang giữ: Lock() phải chờ tất cả người đọc xong
// => Ghi vào dữ liệu thì không ai khác được đọc (sẽ đọc phải dữ liệu đang sửa dở), nhưng đọc với đọc thì không ảnh hưởng nhau
// =========================

type Watcher struct {
	cfg         Config

	// - rulesMu là khoá bảo vệ 2 field rules và rulesModTime
	rulesMu     sync.RWMutex
	rules       []Rule
	rulesModTime    time.Time

	fileLocks   sync.Map

	// - toastMu là khoá bảo vệ field lastToasted
	toastMu     sync.Mutex

	// - Mỗi lần muốn khởi tạo giá trị của thằng lastToasted thì bắt buộc phải dùng make
	// - make là bước tạo ra cái map thật để ghi vào được. make(...) là cách phổ biến hơn khi map bắt đầu rỗng
	// + Vì sao Watcher bắt buộc phải có?
	// - notifyAsync ghi vào map này mỗi khi bắn thông báo: w.lastToasted[key] = time.Now() // ghi vào map
	lastToasted map[string]time.Time
}

// - Go không có constructor, chỉ có quy ước đặt tên NewXxx
// - Go không có class hay new Class(). Thay vào đó, người ta viết một hàm bình thường tên NewTên để tạo và trả về giá trị
// - Hàm này trả về 2 giá trị (*Watcher, error) thay cho try/catch
// - Go không có exception. Hàm nào có thể thất bại thì trả thêm một giá trị error ở cuối
// 			- Thành công: error là nil (tương đương "không có lỗi")
// 			- Thất bại: error có nội dung, và giá trị còn lại thường là nil

// + w := &Watcher{...}: tạo struct và lấy con trỏ luôn
// + Watcher{...} tạo Watcher, & lấy địa chỉ → w có kiểu *Watcher
// + := vừa khai báo vừa gán, giống const w = ... trong typescript (nhưng w vẫn đổi được)
func NewWatcher(cfg Config) (*Watcher, error) {
	w := &Watcher{
		// Các field khác như rulesMu, rules, rulesModTime, fileLocks,... không cần điền vì zero value của chúng dùng được ngay
		// Riêng lastToasted bắt buộc phải make(...), nếu không nó là map nil và ghi vào sẽ panic
		cfg:         cfg,
		lastToasted: make(map[string]time.Time),
	}
    // Phần trước dấu ; chạy trước và tạo biến err. Phần sau dấu ; là điều kiện. Biến err chỉ tồn tại trong khối if này, ra ngoài là mất, nên không làm rối code
	if err := w.reloadRulesIfNeeded(true); err != nil {
		// Lỗi: trả nil cho *Watcher (không có Watcher nào dùng được) kèm lỗi
		return nil, err
	}

	// Thành công: trả w kèm nil cho error
	return w, nil
}

// reloadRulesIfNeeded tự động nạp lại rules.json nếu file có thay đổi (Hot-Reload)
// và kết hợp với các rule truyền động qua tham số dòng lệnh (-watch).
func (w *Watcher) reloadRulesIfNeeded(force bool) error {
	var fileModTime time.Time
	var fileRules []Rule

	if w.cfg.RulesPath != "" {
		info, err := os.Stat(w.cfg.RulesPath)
		if err != nil {
			if !os.IsNotExist(err) || w.cfg.InlineRules == "" {
				return fmt.Errorf("không thể đọc file cấu hình %q: %w", w.cfg.RulesPath, err)
			}
		} else {
			fileModTime = info.ModTime()
			w.rulesMu.RLock()
			unchanged := !force && !fileModTime.After(w.rulesModTime)
			w.rulesMu.RUnlock()
			if unchanged {
				return nil
			}

			raw, err := os.ReadFile(w.cfg.RulesPath)
			if err != nil {
				return fmt.Errorf("lỗi đọc %q: %w", w.cfg.RulesPath, err)
			}
			parsed, err := parseRulesJSON(raw, w.cfg)
			if err != nil {
				return fmt.Errorf("lỗi cú pháp trong %q: %w", w.cfg.RulesPath, err)
			}
			fileRules = parsed
		}
	}

	inlineRules := parseInlineRules(w.cfg.InlineRules, w.cfg)
	merged := mergeRules(fileRules, inlineRules)
	if len(merged) == 0 {
		return errors.New("không có rule hợp lệ nào được cấu hình (kiểm tra rules.json hoặc cờ -watch)")
	}

	w.rulesMu.Lock()
	w.rules = merged
	w.rulesModTime = fileModTime
	w.rulesMu.Unlock()

	if !force {
		log.Printf("🔄 Đã tự động cập nhật lại cấu hình (%d API rules)", len(merged))
	}
	return nil
}

// matchRules nhận một request, trả về danh sách các Rule khớp với request hiện tại
// - Thoát sớm nếu request hỏng (nil)
// - Kiểm tra xem rules.json có đổi không, đổi thì nạp lại (hot-reload)
// - Duyệt từng rule, giữ lại rule nào khớp URL và method
func (w *Watcher) matchRules(req *http.Request) []Rule {
	if req == nil || req.URL == nil {
		return nil
	}

	// - Kiểm tra hot-reload nhẹ nhàng trước khi match
	// - false = "chỉ nạp lại nếu file đã đổi"
	// - Nếu nạp lỗi (ví dụ bạn đang sửa rules.json dở dang, JSON sai cú pháp), chương trình chỉ ghi log rồi đi tiếp với rule cũ, không return. Nhờ vậy sửa file sai không làm proxy ngừng hoạt động
	// - log.Printf giống console.log có định dạng. %v là chỗ điền giá trị bất kỳ (ở đây là lỗi)
	if err := w.reloadRulesIfNeeded(false); err != nil {
		log.Printf("⚠️ Cảnh báo reload rules: %v (giữ nguyên cấu hình cũ)", err)
	}

	// - req.URL là một struct đã tách sẵn (scheme, host, path...). .String() ghép lại thành chuỗi đầy đủ, ví dụ https://shop.com/api/users?page=1
	fullURL := req.URL.String()
	method := strings.ToUpper(req.Method)

	// - RLock() là khoá đọc (nhiều goroutine cùng đọc được, nhưng chặn người ghi). Cần khoá vì reloadRulesIfNeeded ở goroutine khác có thể đang thay cả danh sách rules đúng lúc ta duyệt
	// - Hẹn trước: lúc hàm thoát thì nhả khoá
	// - Chúng ta sẽ không viết RUnlock() ở cuối hàm. Vì hàm có thể thoát ở nhiều chỗ (nhiều return, hoặc panic)
	// - Quên nhả khoá một lần là mọi request sau bị treo mãi. Đặt defer ngay sau Lock thì không thể quên. So với JS thì nó giống finally, nhưng viết ngay cạnh chỗ khoá thay vì dồn xuống cuối
	// - Quy tắc: Lock() xong thì dòng kế tiếp là defer Unlock()
	w.rulesMu.RLock()
	// - defer nghĩa là: "chạy dòng này khi hàm kết thúc", bất kể kết thúc bằng cách nào
	defer w.rulesMu.RUnlock()

	// Tại sao lại phải khai báo 2 dòng w.rulesMu.RLock() và defer w.rulesMu.RUnlock() vào trong hàm matchRules này nhỉ ?
	// => Trong hàm này, dữ liệu dùng chung là w.rules. Vậy liệu có ai đang ghi vào nó => Chính là hàm reloadRulesIfNeeded
	// - Hàm này chạy khi rules.json bị sửa, và nó chạy trong goroutine của một request nào đó, cùng lúc với các request khác đang duyệt w.rules. Tức là:
	// => Không khoá thì A có thể đọc phải dữ liệu đang bị thay (Go gọi là data race), kết quả sai hoặc crash khó đoán. Có RLock thì B (cần Lock) phải chờ A đọc xong mới được thay
	// => Quy tắc nhận biết nhanh: khoá khi đụng vào field của w (Watcher) (dữ liệu chia sẻ), không cần khoá với biến cục bộ

	// Request A: đang for _, r := range w.rules { ... }   ← đọc giữa chừng
	// Request B: w.rules = merged                         ← thay mất danh sách

	// matched bắt đầu là slice nil, và append làm việc tốt với nil
	var matched []Rule

	// Go chỉ có for, không có while/forEach. range trả về 2 giá trị: chỉ số và phần tử. Ở đây không cần chỉ số nên dùng _ bỏ qua. Tương đương for (const r of rules) trong JS
	for _, r := range w.rules {
		// Giống fullURL.includes(pattern). Lưu ý đây là khớp chuỗi con, không phải regex hay khớp đường dẫn chính xác. Pattern /api/users sẽ khớp cả /api/users/5 và /v2/api/users-old
		if !strings.Contains(fullURL, r.Pattern) {
			// continue: bỏ qua rule này, sang rule kế
			continue
		}

		// Rule này có giới hạn method, mà method của request không nằm trong danh sách → bỏ qua rule
		if len(r.Methods) > 0 && !r.Methods[method] {
			continue
		}

		// Lưu ý phải gán lại: matched = append(matched, r), vì append có thể trả về một slice mới. Viết append(matched, r) mà không gán là kết quả bị vứt đi.
		matched = append(matched, r)

		// r là bản copy: mỗi vòng, r là bản copy của phần tử (nhớ lại: struct bị copy khi gán). Ở đây không sao vì chỉ đọc. Nhưng Rule chứa 2 map, và map thì copy chỉ sao chép tham chiếu, nên các Rule trong matched vẫn dùng chung map với w.rules. Vì code không ghi vào map nên an toàn
	}
	return matched
}

// HandleRequest chuẩn hóa header của các request nằm trong diện theo dõi
// nhằm tránh việc server trả về định dạng nén lạ (Brotli/Zstd) hoặc 304 Not Modified.
func (w *Watcher) HandleRequest(req *http.Request, _ *goproxy.ProxyCtx) (*http.Request, *http.Response) {
	if !isTrackableMethod(req.Method) {
		return req, nil
	}
	matched := w.matchRules(req)
	if len(matched) == 0 {
		return req, nil
	}

	// Chỉ chấp nhận gzip/deflate để đảm bảo luôn giải nén được nội dung
	req.Header.Set("Accept-Encoding", "gzip, deflate")

	if w.cfg.StripCacheHeaders {
		req.Header.Del("If-None-Match")
		req.Header.Del("If-Modified-Since")
	}
	return req, nil
}

// HandleResponse xử lý kết quả trả về từ server, chuẩn hóa dữ liệu và kiểm tra Diff.
func (w *Watcher) HandleResponse(resp *http.Response, ctx *goproxy.ProxyCtx) *http.Response {
	if !shouldInspectResponse(resp, ctx) {
		return resp
	}

	matched := w.matchRules(ctx.Req)
	if len(matched) == 0 {
		return resp
	}

	// Chỉ đọc và giải nén body đúng 1 lần duy nhất cho dù khớp nhiều rule
	bodyBytes, err := extractResponseBody(resp, w.cfg.MaxBodyBytes)
	if err != nil {
		log.Printf("⚠️ Bỏ qua response [%s] do lỗi đọc body: %v", ctx.Req.URL.String(), err)
		return resp
	}
	if len(bytes.TrimSpace(bodyBytes)) == 0 {
		return resp
	}

	for _, rule := range matched {
		if err := w.processRuleMatch(rule, bodyBytes); err != nil {
			log.Printf("❌ Lỗi xử lý rule [%s]: %v", rule.Pattern, err)
		}
	}
	return resp
}

// processRuleMatch thực hiện chuẩn hóa JSON, ghi file Origin hoặc xuất file Diff.
func (w *Watcher) processRuleMatch(rule Rule, rawBody []byte) error {
	normalized, parsedVal := normalizePayload(rawBody, rule.IgnoreKeys)

	// Khóa theo từng file đích để chống Race Condition khi nhiều request tới cùng lúc
	lock := w.getFileLock(rule.OutputPath)
	lock.Lock()
	defer lock.Unlock()

	originBytes, err := os.ReadFile(rule.OutputPath)
	if err != nil {
		if !os.IsNotExist(err) {
			return fmt.Errorf("không thể đọc file origin %q: %w", rule.OutputPath, err)
		}

		// LẦN ĐẦU TIÊN: Ghi file Origin bằng Atomic Write
		if err := writeFileAtomic(rule.OutputPath, normalized); err != nil {
			return fmt.Errorf("không thể ghi file origin %q: %w", rule.OutputPath, err)
		}

		log.Printf("[ORIGIN] 📌 Đã ghi bản gốc: %s -> %s", rule.Pattern, rule.OutputPath)
		w.notifyAsync(
			rule.Pattern+":origin",
			"📌 API Origin Saved",
			fmt.Sprintf("Đã lưu bản gốc: %s", filepath.Base(rule.OutputPath)),
		)
		return nil
	}

	// Chuẩn hóa lại cả dữ liệu trong file Origin (phòng trường hợp user vừa thêm ignore_keys mới)
	normalizedOrigin, originVal := normalizePayload(originBytes, rule.IgnoreKeys)
	if bytes.Equal(normalizedOrigin, normalized) {
		log.Printf("[OK] ✅ Không có thay đổi: %s", rule.Pattern)
		return nil
	}

	// PHÁT HIỆN THAY ĐỔI: Lưu ra file *_diff.ext
	diffPath := buildDiffPath(rule.OutputPath)
	if err := writeFileAtomic(diffPath, normalized); err != nil {
		return fmt.Errorf("không thể ghi file diff %q: %w", diffPath, err)
	}

	diffHint := summarizeJSONDiff(originVal, parsedVal)
	log.Printf("[DIFF!] ⚠️ Phát hiện thay đổi: %s -> %s (%s)", rule.Pattern, diffPath, diffHint)

	toastMsg := fmt.Sprintf("API: %s\nFile: %s\n%s", rule.Pattern, filepath.Base(diffPath), diffHint)
	w.notifyAsync(rule.Pattern+":diff", "⚠️ API Diff Detected!", toastMsg)
	return nil
}

// Hàm này nhận một đường dẫn file và trả về chiếc khoá dành riêng cho file đó. Vì Watcher có field fileLocks là kho chứa "mỗi file một khoá". 
// Hàm này là người giữ kho có nhiệm vụ như sau:
// - 1) File đã có khoá thì trả lại đúng chiếc khoá cũ.
// - 2) File chưa có khoá thì tạo khoá mới, cất vào kho, rồi trả về.

// - Phần (w *Watcher) đứng trước tên hàm gọi là receiver: nó gắn hàm này vào kiểu Watcher
// - w đóng vai trò this. Go không có từ khoá this, bạn tự đặt tên. Quy ước là dùng 1–2 chữ cái đầu của tên kiểu (w cho Watcher, c cho Config)
// - Gọi method bằng dấu chấm như JS: w.getFileLock("...")
// - *Watcher là pointer receiver: method nhận con trỏ, không nhận bản copy. struct chứa khoá thì không được copy
// - Nếu viết func (w Watcher) không có *, mỗi lần gọi method sẽ là một bản copy của Watcher kèm khoá bị copy, coi như không khoá gì
// => Quy tắc nhanh: method cần sửa struct, hoặc struct chứa mutex, hoặc struct lớn, thì dùng *. Gần như mọi method bạn viết sẽ dùng *
// => Vì sao phải có (w *Watcher)? => Vì hàm này cần dùng field fileLocks nằm bên trong Watcher
// - Dấu * trong w *Watcher nghĩa là làm việc trên bản gốc, không phải bản copy. Trong Go, struct bị copy mỗi khi truyền đi. Vì vậy:
//  	=> w *Watcher (có *): hàm nhận bản gốc
// 		=> w Watcher (không *): mỗi lần gọi, hàm nhận một bản photo của Watcher
// 		=> Giống như bạn đưa người khác bản photo của một tờ giấy để họ sửa: họ sửa xong, tờ gốc của bạn vẫn y như cũ
// 		=> Tóm lại: Method gắn vào struct thì cứ dùng *. Đó cũng là cách gần như mọi code Go vẫn viết, và nó chạy đúng như object trong JS mà chúng ta đã quen
func (w *Watcher) getFileLock(targetPath string) *sync.Mutex {
	// + filepath.Clean: chuẩn hoá đường dẫn
	// VD 1: filepath.Clean("./out/../out//users.json")  // "out/users.json"
	// VD 2: filepath.Clean("out/users.json")            // "out/users.json"
	// => Hai chuỗi khác nhau nhưng cùng trỏ tới một file. Không chuẩn hoá thì chúng thành 2 key khác nhau và nhận 2 khoá khác nhau, khi đó khoá mất tác dụng. Nó tương đương path.normalize() trong Node
	cleanPath := filepath.Clean(targetPath)

	// + Hàm trả về nhiều giá trị, và _ để bỏ bớt
	// - Hàm Go có thể trả về nhiều giá trị cùng lúc. LoadOrStore trả về 2 giá trị:
	// - actual: chiếc khoá sẽ được dùng (cũ hoặc mới)
	// - loaded: true nếu khoá đã có sẵn từ trước, false nếu vừa được cất vào
	// - LoadOrStore gộp "kiểm tra + cất" thành một thao tác nguyên tử (atomic), không ai chen vào giữa được. Dù 100 goroutine cùng gọi, tất cả đều nhận đúng một chiếc khoá duy nhất
    // - &sync.Mutex{}: tạo giá trị rồi lấy địa chỉ. sync.Mutex{} tạo một mutex mới (dạng struct literal như Config{...}). & ở phía trước nghĩa là lấy địa chỉ của nó, tức là tạo ra con trỏ *sync.Mutex
	// - Tại sao phải cất con trỏ mà không cất mutex trực tiếp? Lại là quy tắc "mutex không được copy". Nếu cất giá trị, mỗi lần Load ra bạn nhận một bản copy của mutex. Mỗi goroutine sẽ khoá bản copy của riêng mình, tức là không khoá gì cả. Cất con trỏ thì mọi người cùng trỏ tới một mutex thật duy nhất
	
	// - &sync.Mutex{}

	// Trong đó:
	// + sync.Mutex      // chỉ là tên kiểu, chưa có cái khoá nào cả
	// + sync.Mutex{}    // tạo ra một cái khoá mới

	// Nó tương ứng với:
	// - Mutex           // chỉ là tên class
	// - new Mutex()     // tạo ra một object thật

	// &: lấy địa chỉ, để mọi người dùng chung bản gốc
	// & là cặp với * mà bạn vừa hỏi:
	// * nằm trong kiểu (*sync.Mutex) nghĩa là "đây là con trỏ tới bản gốc".
	// & nằm trước giá trị (&sync.Mutex{}) là hành động tạo ra con trỏ đó.

	// Ngoài ra, hàm đã hứa trả về *sync.Mutex (có *), nên thứ được cất vào tủ cũng phải là &... thì mới khớp kiểu

	actual, _ := w.fileLocks.LoadOrStore(cleanPath, &sync.Mutex{})

	// - Tương đương với return actual as Mutex trong TS
	// - Khác biệt lớn: as của TS chỉ để lừa compiler và mất đi lúc chạy. Type assertion của Go thì được kiểm tra thật lúc chạy. Sai kiểu là panic
	// - Ở đầu hàm, chúng ta đã hứa sẽ trả về một *sync.Mutex. Nên chúng ta phải viết return actual.(*sync.Mutex)
	// - Nhưng sync.Map lưu được mọi loại dữ liệu, nên thứ nó trả ra cho chúng ta có kiểu là any, nghĩa là "cái gì cũng được". Go không chịu trả một thứ "cái gì cũng được" khi chúng ta đã hứa trả một kiểu cụ thể
	return actual.(*sync.Mutex)
}

// notifyAsync gửi Toast Notification bất đồng bộ kèm cơ chế Cooldown chống spam.
func (w *Watcher) notifyAsync(key, title, message string) {
	w.toastMu.Lock()
	last, exists := w.lastToasted[key]
	if exists && time.Since(last) < w.cfg.ToastCooldown {
		w.toastMu.Unlock()
		return
	}
	w.lastToasted[key] = time.Now()
	w.toastMu.Unlock()

	go func() {
		if err := beeep.Notify(title, message, ""); err != nil {
			log.Printf("⚠️ Không thể hiển thị Toast: %v", err)
		}
	}()
}

// ============================================================================
// Các hàm xử lý HTTP, Giải nén & Chuẩn hóa JSON (Pure / Reusable Functions)
// ============================================================================

// Hàm này nhận vào HTTP method của request ("GET", "POST"...) và trả lời câu hỏi "request này có đáng để theo dõi không?". Bốn method OPTIONS, HEAD, CONNECT, TRACE trả false, mọi method còn lại trả true
func isTrackableMethod(method string) bool {
	switch strings.ToUpper(method) {
	case http.MethodOptions, http.MethodHead, http.MethodConnect, http.MethodTrace:
		return false
	default:
		return true
	}
}

func shouldInspectResponse(resp *http.Response, ctx *goproxy.ProxyCtx) bool {
	if resp == nil || resp.Body == nil || ctx == nil || ctx.Req == nil || ctx.Req.URL == nil {
		return false
	}
	if !isTrackableMethod(ctx.Req.Method) {
		return false
	}
	// Bỏ qua các response không mang dữ liệu chuẩn (304 Not Modified, 204 No Content, 4xx, 5xx)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 ||
		resp.StatusCode == http.StatusNoContent ||
		resp.StatusCode == http.StatusNotModified {
		return false
	}
	return true
}

// extractResponseBody đọc an toàn toàn bộ stream với giới hạn dung lượng,
// khôi phục nguyên trạng resp.Body cho trình duyệt và giải nén gzip/deflate nếu có.
func extractResponseBody(resp *http.Response, maxBytes int64) ([]byte, error) {
	origBody := resp.Body
	defer origBody.Close()

	rawBytes, err := io.ReadAll(io.LimitReader(origBody, maxBytes+1))
	if err != nil {
		resp.Body = io.NopCloser(bytes.NewReader(rawBytes))
		return nil, err
	}

	// Nếu vượt quá dung lượng cho phép: nối lại phần đã đọc + phần còn lại trả về cho trình duyệt
	if int64(len(rawBytes)) > maxBytes {
		resp.Body = struct {
			io.Reader
			io.Closer
		}{
			Reader: io.MultiReader(bytes.NewReader(rawBytes), origBody),
			Closer: origBody,
		}
		return nil, fmt.Errorf("kích thước body vượt quá giới hạn %d bytes", maxBytes)
	}

	// Khôi phục lại Body cho trình duyệt
	resp.Body = io.NopCloser(bytes.NewReader(rawBytes))

	encoding := strings.ToLower(strings.TrimSpace(resp.Header.Get("Content-Encoding")))
	switch encoding {
	case "gzip":
		gr, err := gzip.NewReader(bytes.NewReader(rawBytes))
		if err != nil {
			return nil, fmt.Errorf("lỗi tạo gzip reader: %w", err)
		}
		defer gr.Close()
		return io.ReadAll(io.LimitReader(gr, maxBytes))

	case "deflate":
		fr := flate.NewReader(bytes.NewReader(rawBytes))
		defer fr.Close()
		return io.ReadAll(io.LimitReader(fr, maxBytes))

	default:
		return rawBytes, nil
	}
}

// normalizePayload giải mã JSON với UseNumber (bảo toàn độ chính xác số nguyên lớn),
// loại bỏ các trường động trong ignoreKeys, và sắp xếp lại toàn bộ key theo thứ tự alphabet.
func normalizePayload(raw []byte, ignoreKeys map[string]bool) ([]byte, any) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return trimmed, nil
	}

	decoder := json.NewDecoder(bytes.NewReader(trimmed))
	decoder.UseNumber()

	var data any
	if err := decoder.Decode(&data); err != nil {
		// Nếu không phải JSON hợp lệ (ví dụ plain text / HTML), trả về dữ liệu đã trim
		return trimmed, nil
	}

	if len(ignoreKeys) > 0 {
		data = stripIgnoredKeys(data, ignoreKeys)
	}

	formatted, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return trimmed, data
	}
	return formatted, data
}

// Hàm này nhận một cục JSON đã parse (có thể lồng nhiều tầng) và trả về bản đã xoá hết các key nằm trong danh sách bỏ qua (như timestamp, requestId), ở mọi độ sâu
// Nó dùng đệ quy: gặp object thì duyệt từng key, gặp mảng thì duyệt từng phần tử, và mỗi con lại gọi chính hàm này
func stripIgnoredKeys(v any, ignoreKeys map[string]bool) any {
	// Chữ type ở đây là từ khoá. Viết v.(type) ngoài switch là lỗi compile. Trong đó val là biến mới, type hỏi "v là kiểu gì?". v.(type) chính là họ hàng của actual.(*sync.Mutex)
	// So với JS:
	// - if (Array.isArray(v)) { ... }            // hỏi: có phải mảng không?
	// - else if (v && typeof v === "object") { ... }   // hỏi: có phải object không?
	// => Go gom tất cả vào một switch gọn hơn, và sau khi hỏi xong thì compiler biết chắc kiểu, không cần as
	switch val := v.(type) {
	
	// v là object → val có kiểu map[string]any
	case map[string]any:
		// Ví dụ: 
		// val := map[string]any{
		//     "name":      "An",
		//     "timestamp": 111,
		//     "address":   map[string]any{"city": "HCM", "timestamp": 222},
		// }
		// => Mục tiêu: xoá mọi key timestamp, kể cả key nằm sâu bên trong address

		// + Bước 0: tạo map rỗng để hứng kết quả. Lúc này: cleaned = {}

		// + Bước 1: duyệt từng key (thứ tự có thể khác, nhưng kết quả như nhau)
		// Lượt		k	            child				 ignoreKeys[ToLower(k)]			Việc xảy ra
		// 1		"name"		    "An"				 false	                        Không bị ignore → cleaned["name"] = stripIgnoredKeys("An") → chuỗi rơi vào default, trả nguyên "An"
		// 2		"timestamp"	    111	                 true	                        continue → bỏ qua, không chép sang cleaned
		// 3		"address"	    {city, timestamp}	 false	                        Không bị ignore → gọi lại chính hàm với child (xem bước 2)

		// Bước 2: lượt 3 đi sâu vào address (đệ quy)
		// stripIgnoredKeys chạy lại từ đầu với val = {"city": "HCM", "timestamp": 222}:
		// k				Việc xảy ra
		// "city"			Giữ lại → cleaned2["city"] = "HCM"
		// "timestamp"		continue → bỏ
		// => Trả về {"city": "HCM"}, rồi quay lại bước 1 và gán cleaned["address"] = {"city": "HCM"}

		// Kết quả cuối cùng:
		// {
		//   "name": "An",
		//   "address": { "city": "HCM" }
		// }

		// - make với tham số thứ hai là dung lượng dự trù: báo trước sẽ chứa tối đa len(val) phần tử để Go cấp phát một lần, khỏi phải nới rộng nhiều lần
		// - Nếu bỏ len(val) thì code vẫn hoạt động hoàn toàn bình thường. Việc có thêm len(val) báo trước  "mình sắp bỏ khoảng chừng bấy nhiêu phần tử vào", để Go cấp phát đủ chỗ một lần. Không báo thì map bắt đầu nhỏ, rồi cứ đầy lại phải nới rộng và chép dữ liệu sang chỗ mới, lặp lại nhiều lần
		// Giống như dọn nhà: biết trước có 100 món đồ thì thuê luôn xe tải đủ lớn, thay vì mang từng thùng nhỏ rồi phải đổi xe nhiều lần.
		cleaned := make(map[string]any, len(val))

		// - range trên map trả key và value (khác với slice là chỉ số và phần tử)
		for k, child := range val {
			// Kiểm tra k có trong danh sách → true → continue (bỏ key này)
			if ignoreKeys[strings.ToLower(k)] {
				continue
			}

			// - Giá trị con (child) được đệ quy xử lý tiếp, nên key nằm sâu bao nhiêu tầng cũng bị bỏ
			cleaned[k] = stripIgnoredKeys(child, ignoreKeys)
		}
		return cleaned

	// v là mảng   → val có kiểu []any
	case []any:
		// Ví dụ:
		// val := []any{
		//     map[string]any{"id": 1, "timestamp": 111},
		//     map[string]any{"id": 2, "timestamp": 222},
		// }

		// Lượt	i	item					Việc xảy ra
		// 1	0	{id:1, timestamp:111}	Làm sạch → {id:1}, ghi đè vào val[0]
		// 2	1	{id:2, timestamp:222}	Làm sạch → {id:2}, ghi đè vào val[1]

		// Kết quả cuối cùng:
		// [ {id:1}, {id:2} ]   ← vẫn là mảng cũ, chỉ có phần tử bên trong được thay

		// Chỉ cần thay từng phần tử bằng bản đã làm sạch, mảng không bị đổi độ dài. Khác nhánh object (tạo map mới), nhánh này ghi đè thẳng lên slice gốc, vì slice chia sẻ mảng bên dưới
		for i, item := range val {
			val[i] = stripIgnoredKeys(item, ignoreKeys)
		}
		return val
	
	// Còn lại (string, số, bool, nil) → val vẫn là any
	// Chuỗi, số, bool, nil không có key con nên trả nguyên xi. Đây cũng là điều kiện dừng của đệ quy
	default:
		return v
	}
}

// summarizeJSONDiff tìm nhanh các đường dẫn JSON bị thay đổi để hiển thị lên Toast ngắn gọn.
func summarizeJSONDiff(oldVal, newVal any) string {
	if oldVal == nil || newVal == nil {
		return "Nội dung phản hồi thay đổi"
	}
	var diffs []string
	collectDiffPaths("$", oldVal, newVal, &diffs, 3)
	if len(diffs) == 0 {
		return "Thay đổi cấu trúc dữ liệu"
	}
	return "Thay đổi tại: " + strings.Join(diffs, ", ")
}

func collectDiffPaths(path string, a, b any, out *[]string, maxDiffs int) {
	if len(*out) >= maxDiffs {
		return
	}
	switch va := a.(type) {
	case map[string]any:
		vb, ok := b.(map[string]any)
		if !ok {
			*out = append(*out, path)
			return
		}
		keys := make([]string, 0, len(va)+len(vb))
		seen := make(map[string]bool)
		for k := range va {
			keys = append(keys, k)
			seen[k] = true
		}
		for k := range vb {
			if !seen[k] {
				keys = append(keys, k)
			}
		}
		sort.Strings(keys)

		for _, k := range keys {
			if len(*out) >= maxDiffs {
				return
			}
			subPath := path + "." + k
			valA, inA := va[k]
			valB, inB := vb[k]
			if !inA || !inB {
				*out = append(*out, subPath)
				continue
			}
			collectDiffPaths(subPath, valA, valB, out, maxDiffs)
		}

	case []any:
		vb, ok := b.([]any)
		if !ok || len(va) != len(vb) {
			*out = append(*out, fmt.Sprintf("%s (len %d->%d)", path, len(va), lenSlice(b)))
			return
		}
		for i := range va {
			if len(*out) >= maxDiffs {
				return
			}
			collectDiffPaths(fmt.Sprintf("%s[%d]", path, i), va[i], vb[i], out, maxDiffs)
		}

	default:
		if fmt.Sprintf("%v", a) != fmt.Sprintf("%v", b) {
			*out = append(*out, path)
		}
	}
}

// v.([]any) trả về 2 giá trị: là s và ok
// Trong đó:
// Biến		Trả lời câu hỏi								Kiểu
// s		"Lấy ra được cái gì?"						[]any
// ok		"Mở hộp có thành công không?"				bool

// Vì sao không gộp thành một?
// - Vì chỉ nhìn s thì không biết thất bại hay không ? 
// - Khi v không phải mảng, s là zero value (nil). Nhưng nil cũng là giá trị của một mảng rỗng hợp lệ:

// Ví dụ:
// v1 := []any{}     // Là mảng, nhưng rỗng
// v2 := "hello"     // Không phải mảng

// s1, ok1 := v1.([]any)   // s1 = rỗng, ok1 = true
// s2, ok2 := v2.([]any)   // s2 = nil,  ok2 = false
// => Nếu chỉ có s, hai trường hợp này trông giống nhau (đều rỗng) nhưng ý nghĩa khác hẳn. ok là thứ phân biệt chúng.
// => Công thức chung của Go: Mẫu chung của Go: "giá trị" + "có hợp lệ không" tách thành 2 biến, 
// thay cho việc trả undefined/null như JS.

// + Hàm này sẽ tương đương như sau bên TS:
// function lenSlice(v: unknown): number {
//   return Array.isArray(v) ? v.length : 0;
// }

func lenSlice(v any) int {
	// Nếu v là mảng JSON (ok == true) thì lấy độ dài, không phải thì trả 0
	if s, ok := v.([]any); ok {
		return len(s)
	}
	return 0
}

// ============================================================================
// Các hàm quản lý File I/O & Parse Cấu hình động
// ============================================================================

// writeFileAtomic ghi dữ liệu ra file tạm cùng thư mục rồi rename sang file đích
// nhằm đảm bảo tính nguyên tử (Atomic), không bao giờ tạo ra file hỏng/ghi dở.
func writeFileAtomic(targetPath string, content []byte) error {
	dir := filepath.Dir(targetPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	tmpFile, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return err
	}
	tmpPath := tmpFile.Name()

	defer func() {
		if tmpPath != "" {
			_ = os.Remove(tmpPath)
		}
	}()

	if _, err := tmpFile.Write(content); err != nil {
		_ = tmpFile.Close()
		return err
	}
	if err := tmpFile.Sync(); err != nil {
		_ = tmpFile.Close()
		return err
	}
	if err := tmpFile.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmpPath, 0644); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, targetPath); err != nil {
		return err
	}
	tmpPath = "" // Đánh dấu đã rename thành công để defer không xóa
	return nil
}

func buildDiffPath(targetPath string) string {
	ext := filepath.Ext(targetPath)
	if ext == "" {
		return targetPath + "_diff.json"
	}
	return strings.TrimSuffix(targetPath, ext) + "_diff" + ext
}

// parseRulesJSON hỗ trợ cả định dạng chuỗi đơn giản {"/api": "./out.json"}
// lẫn định dạng object nâng cao {"/api": {"output": "./out.json", "methods": ["GET"], "ignore_keys": ["timestamp"]}}.
func parseRulesJSON(raw []byte, cfg Config) ([]Rule, error) {
	var rawMap map[string]json.RawMessage
	if err := json.Unmarshal(raw, &rawMap); err != nil {
		return nil, err
	}

	var rules []Rule
	for pattern, msg := range rawMap {
		pattern = strings.TrimSpace(pattern)
		if pattern == "" {
			continue
		}

		// Thử parse kiểu chuỗi đơn giản trước
		var simpleTarget string
		if err := json.Unmarshal(msg, &simpleTarget); err == nil {
			rules = append(rules, buildRule(pattern, simpleTarget, nil, cfg.IgnoreKeys, cfg.OutputDir))
			continue
		}

		// Nếu không phải chuỗi, parse kiểu object nâng cao
		var adv RuleConfigJSON
		if err := json.Unmarshal(msg, &adv); err != nil {
			return nil, fmt.Errorf("rule %q không hợp lệ: %w", pattern, err)
		}
		combinedIgnore := append([]string{}, cfg.IgnoreKeys...)
		combinedIgnore = append(combinedIgnore, adv.IgnoreKeys...)
		rules = append(rules, buildRule(pattern, adv.Output, adv.Methods, combinedIgnore, cfg.OutputDir))
	}
	return rules, nil
}

// parseInlineRules cho phép truyền nhanh rule từ CLI:
// Ví dụ: -watch "auction-section-list=./output/auction.json,/api/v1/users"
func parseInlineRules(inline string, cfg Config) []Rule {
	if strings.TrimSpace(inline) == "" {
		return nil
	}
	var rules []Rule
	entries := strings.Split(inline, ",")
	for _, entry := range entries {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		var pattern, target string
		if parts := strings.SplitN(entry, "=", 2); len(parts) == 2 {
			pattern = strings.TrimSpace(parts[0])
			target = strings.TrimSpace(parts[1])
		} else {
			pattern = entry
		}
		if pattern != "" {
			rules = append(rules, buildRule(pattern, target, nil, cfg.IgnoreKeys, cfg.OutputDir))
		}
	}
	return rules
}

// - Tạo sẵn một bộ lọc regex để tìm các ký tự không an toàn khi dùng làm tên file (khoảng trắng, /, ?, :, *...)
// VD: _api_users_page_1 => api_users_page_1.json

// Go có hai hàm:

// Hàm								Khi regex sai
// regexp.Compile(...)				Trả về (*Regexp, error) để bạn tự xử lý
// regexp.MustCompile(...)			Panic ngay

// - Biến này nằm ngoài mọi hàm, nên chỉ được biên dịch một lần khi chương trình khởi động, rồi mọi lần gọi buildRule dùng lại. Biên dịch regex khá tốn, đặt trong hàm là phí vì mỗi lần gọi lại biên dịch lại. Tương tự việc bạn khai báo const re = /.../ ở đầu file JS thay vì trong hàm.
// - Regex của Go là an toàn khi dùng đồng thời nhiều goroutine, nên dùng chung một biến không cần khoá
var unsafeFileChars = regexp.MustCompile(`[^a-zA-Z0-9._-]+`)

func buildRule(pattern, outputPath string, methods, ignoreKeys []string, defaultOutDir string) Rule {
	target := strings.TrimSpace(outputPath)
	if target == "" {
		safeName := strings.Trim(unsafeFileChars.ReplaceAllString(pattern, "_"), "_")
		if safeName == "" {
			safeName = "api_response"
		}
		if filepath.Ext(safeName) == "" {
			safeName += ".json"
		}
		target = filepath.Join(defaultOutDir, safeName)
	}

	methodMap := make(map[string]bool, len(methods))
	for _, m := range methods {
		if m = strings.ToUpper(strings.TrimSpace(m)); m != "" {
			methodMap[m] = true
		}
	}

	ignoreMap := make(map[string]bool, len(ignoreKeys))
	for _, k := range ignoreKeys {
		if k = strings.ToLower(strings.TrimSpace(k)); k != "" {
			ignoreMap[k] = true
		}
	}

	return Rule{
		Pattern:    pattern,
		OutputPath: filepath.Clean(target),
		Methods:    methodMap,
		IgnoreKeys: ignoreMap,
	}
}

// mergeRules gộp danh sách rule (ưu tiên CLI inline ghi đè file) và sắp xếp
// theo độ dài pattern giảm dần để pattern cụ thể hơn được kiểm tra trước.
func mergeRules(fileRules, inlineRules []Rule) []Rule {
	byPattern := make(map[string]Rule, len(fileRules)+len(inlineRules))
	for _, r := range fileRules {
		byPattern[r.Pattern] = r
	}
	for _, r := range inlineRules {
		byPattern[r.Pattern] = r
	}

	merged := make([]Rule, 0, len(byPattern))
	for _, r := range byPattern {
		merged = append(merged, r)
	}

	sort.Slice(merged, func(i, j int) bool {
		if len(merged[i].Pattern) != len(merged[j].Pattern) {
			return len(merged[i].Pattern) > len(merged[j].Pattern)
		}
		return merged[i].Pattern < merged[j].Pattern
	})
	return merged
}

func ensureCACert(caFile string) error {
	if _, err := os.Stat(caFile); err == nil {
		return nil
	} else if !os.IsNotExist(err) {
		return err
	}
	if err := writeFileAtomic(caFile, goproxy.CA_CERT); err != nil {
		return err
	}
	log.Printf("🔑 Đã tạo file chứng chỉ %q. Hãy import vào trình duyệt/Keychain để bắt HTTPS!", caFile)
	return nil
}

func parseFlags() Config {
	addr := flag.String("addr", "127.0.0.1:8888", "Địa chỉ và cổng lắng nghe của Proxy")
	rulesPath := flag.String("rules", "rules.json", "Đường dẫn tới file cấu hình rules JSON")
	watch := flag.String("watch", "", "Danh sách rule truyền động (VD: 'api/users=./out/u.json,api/orders')")
	outDir := flag.String("out-dir", "./output", "Thư mục lưu file mặc định khi không chỉ định đường dẫn")
	caFile := flag.String("ca-file", "ca.crt", "Đường dẫn xuất file chứng chỉ CA")
	ignore := flag.String("ignore-keys", "", "Các JSON key động cần bỏ qua khi so sánh, cách nhau bởi dấu phẩy (VD: 'timestamp,requestId')")
	maxBodyMB := flag.Int64("max-body-mb", 10, "Giới hạn kích thước response body tối đa (MB)")
	cooldown := flag.Duration("toast-cooldown", 3*time.Second, "Thời gian nghỉ tối thiểu giữa 2 lần bắn Toast cho cùng 1 API")
	stripCache := flag.Bool("strip-cache", true, "Xóa If-None-Match/If-Modified-Since để tránh server trả về 304 rỗng")
	flag.Parse()

	var ignoreKeys []string
	if strings.TrimSpace(*ignore) != "" {
		ignoreKeys = strings.Split(*ignore, ",")
	}

	return Config{
		Addr:          *addr,
		RulesPath:     *rulesPath,
		InlineRules:   *watch,
		OutputDir:     *outDir,
		CAFile:        *caFile,
		IgnoreKeys:    ignoreKeys,
		MaxBodyBytes:  (*maxBodyMB) * 1024 * 1024,
		ToastCooldown: *cooldown,
		StripCacheHeaders: *stripCache,
	}
}

func main() {
	cfg := parseFlags()

	if err := ensureCACert(cfg.CAFile); err != nil {
		log.Fatalf("❌ Không thể khởi tạo chứng chỉ CA (%s): %v", cfg.CAFile, err)
	}

	watcher, err := NewWatcher(cfg)
	if err != nil {
		log.Fatalf("❌ Khởi tạo Watcher thất bại: %v", err)
	}

	proxy := goproxy.NewProxyHttpServer()
	proxy.Verbose = false
	proxy.OnRequest().HandleConnect(goproxy.AlwaysMitm)
	proxy.OnRequest().DoFunc(watcher.HandleRequest)
	proxy.OnResponse().DoFunc(watcher.HandleResponse)

	srv := &http.Server{
		Addr:              cfg.Addr,
		Handler:           proxy,
		ReadHeaderTimeout: 15 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	go func() {
		log.Printf("🚀 API Watcher đang chạy tại http://%s (Theo dõi %d API rules)...", cfg.Addr, len(watcher.rules))
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("❌ Lỗi khởi chạy HTTP Proxy Server: %v", err)
		}
	}()

	<-ctx.Done()
	log.Println("🛑 Đang dừng API Watcher an toàn...")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		log.Printf("⚠️ Lỗi khi đóng server: %v", err)
	}
}