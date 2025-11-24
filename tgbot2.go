package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/md5"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/andybalholm/brotli"
	tgbotapi "github.com/go-telegram-bot-api/telegram-bot-api/v5"
	"github.com/klauspost/compress/zstd"
)

// Configuration
var (
	TurnstileSiteKey = "0x4AAAAAABvS1997-yKQFdEG"
	DebugMode        = os.Getenv("DEBUG") == "1"
	DebugSMS         = os.Getenv("DEBUG_SMS") == "1"
	HWIDWhitelistURL = "https://pastebin.com/raw/MVSLL1cq"
	AdminChatID      int64
)

const (
	DefaultTimeout      = 120 * time.Second
	TurnstileSiteURL    = "https://nustargame.com/home/login"
	SMSEndpoint         = "https://io.nustargame.com/common/api/sms/send/short/msg"
	LoginEndpoint       = "https://io.nustargame.com/common/api/player/login"
	BackhallEndpoint    = "https://io.nustargame.com/common/api/jili/backhall"
	SetPasswordEndpoint = "https://io.nustargame.com/common/api/set/phone/passwd"
	CreditsPerAccount   = 1 // Credits cost per account creation
)

// User data structure
type UserData struct {
	ChatID          int64     `json:"chat_id"`
	Credits         int       `json:"credits"`
	DefaultPassword string    `json:"default_password"`
	TotalCreated    int       `json:"total_created"`
	LastUsed        time.Time `json:"last_used"`
	IsAdmin         bool      `json:"is_admin"`
}

// User session management
type UserSession struct {
	ChatID          int64
	State           string
	Phone           string
	Password        string
	SMSCode         string
	AccountCount    int
	CurrentAccount  int
	Fingerprint     Fingerprint
	TurnstileToken  string
	CreatedAccounts []string
	LastActivity    time.Time
	IsAdmin         bool
	UseDefaultPass  bool
}

type BotConfig struct {
	TelegramToken string `json:"telegram_token"`
	AdminChatID   int64  `json:"admin_chat_id"`
	APIKey        string `json:"api_key"`
	ProxyURL      string `json:"proxy_url"`
}

var (
	sessions     = make(map[int64]*UserSession)
	sessionMutex sync.RWMutex
	users        = make(map[int64]*UserData)
	usersMutex   sync.RWMutex
	botConfig    BotConfig
)

// States
const (
	StateIdle                   = "idle"
	StateAwaitingPassword       = "awaiting_password"
	StateAwaitingCount          = "awaiting_count"
	StateAwaitingPhone          = "awaiting_phone"
	StateAwaitingSMS            = "awaiting_sms"
	StateProcessing             = "processing"
	StateAdminAwaitingHWID      = "admin_awaiting_hwid"
	StateAdminAwaitingProxy     = "admin_awaiting_proxy"
	StateAdminAwaitingCredits   = "admin_awaiting_credits"
	StateAdminAwaitingChatID    = "admin_awaiting_chatid"
	StateSettingDefaultPassword = "setting_default_password"
	StateAdminAwaitingBroadcast = "admin_awaiting_broadcast"
)

// Fingerprint struct
type Fingerprint struct {
	DeviceBrand   string
	DeviceModel   string
	OSVersion     string
	DeviceID      string
	UserAgent     string
	AppVersion    string
	SecCHUA       string
	SecCHMobile   string
	SecCHPlatform string
	Timezone      string
	Language      string
}

func loadConfig() error {
	data, err := os.ReadFile("config.json")
	if err != nil {
		if os.IsNotExist(err) {
			// Create default config
			defaultConfig := BotConfig{
				TelegramToken: "YOUR_BOT_TOKEN_HERE",
				AdminChatID:   0,
				APIKey:        "YOUR_SOLVERIFY_API_KEY",
				ProxyURL:      "",
			}
			configData, _ := json.MarshalIndent(defaultConfig, "", "  ")
			os.WriteFile("config.json", configData, 0644)
			return fmt.Errorf("config.json created with default values - please edit it with your credentials")
		}
		return err
	}

	if err := json.Unmarshal(data, &botConfig); err != nil {
		return fmt.Errorf("failed to parse config.json: %v", err)
	}

	// Validate config
	if botConfig.TelegramToken == "" || botConfig.TelegramToken == "YOUR_BOT_TOKEN_HERE" {
		return fmt.Errorf("please set a valid telegram_token in config.json")
	}
	if botConfig.AdminChatID == 0 {
		return fmt.Errorf("please set admin_chat_id in config.json")
	}
	if botConfig.APIKey == "" || botConfig.APIKey == "YOUR_SOLVERIFY_API_KEY" {
		return fmt.Errorf("please set a valid api_key in config.json")
	}

	return nil
}

func saveConfig() error {
	data, err := json.MarshalIndent(botConfig, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile("config.json", data, 0644)
}

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	log.Println("Loading configuration...")
	if err := loadConfig(); err != nil {
		log.Fatalf("Configuration error: %v", err)
	}

	log.Println("Configuration loaded successfully!")
	log.Printf("Admin Chat ID: %d", botConfig.AdminChatID)
	log.Printf("Proxy: %s", func() string {
		if botConfig.ProxyURL != "" {
			return "Enabled"
		}
		return "Disabled"
	}())

	AdminChatID = botConfig.AdminChatID

	log.Println("Loading users database...")
	if err := loadUsers(); err != nil {
		log.Printf("Warning: Failed to load users: %v", err)
	}

	log.Println("Connecting to Telegram...")
	bot, err := tgbotapi.NewBotAPI(botConfig.TelegramToken)
	if err != nil {
		log.Fatalf("Failed to create bot: %v\n\nPlease check your telegram_token in config.json\nGet your token from @BotFather on Telegram", err)
	}

	bot.Debug = DebugMode
	log.Printf("✅ Authorized on account @%s", bot.Self.UserName)
	log.Printf("Bot Name: %s", bot.Self.FirstName)

	go func() {
		ticker := time.NewTicker(30 * time.Minute)
		for range ticker.C {
			sessionMutex.Lock()
			for chatID, session := range sessions {
				if time.Since(session.LastActivity) > 1*time.Hour {
					delete(sessions, chatID)
				}
			}
			sessionMutex.Unlock()
		}
	}()

	u := tgbotapi.NewUpdate(0)
	u.Timeout = 60

	updates := bot.GetUpdatesChan(u)

	log.Println("🤖 Bot started successfully and ready to receive messages!")
	log.Println("Send /start to your bot to begin")

	for update := range updates {
		if update.Message != nil {
			handleMessage(bot, update.Message)
		} else if update.CallbackQuery != nil {
			handleCallbackQuery(bot, update.CallbackQuery)
		}
	}
}

// SolverifyClient
type SolverifyClient struct {
	BaseURL    string
	ClientKey  string
	HTTPClient *http.Client
}

func NewSolverifyClient(baseURL, clientKey string) *SolverifyClient {
	if !strings.HasPrefix(baseURL, "http") {
		baseURL = "https://" + baseURL
	}
	return &SolverifyClient{
		BaseURL:    strings.TrimRight(baseURL, "/"),
		ClientKey:  clientKey,
		HTTPClient: &http.Client{Timeout: 60 * time.Second},
	}
}

func (c *SolverifyClient) CreateTurnstileTask(ctx context.Context, siteURL, siteKey, userAgent string) (string, error) {
	body := map[string]any{
		"clientKey": c.ClientKey,
		"task": map[string]any{
			"type":       "turnstile",
			"websiteURL": siteURL,
			"websiteKey": siteKey,
		},
	}
	if userAgent != "" {
		task := body["task"].(map[string]any)
		task["solutionParams"] = map[string]any{"userAgent": userAgent, "pageAction": "login"}
	}
	bs, _ := json.Marshal(body)
	req, _ := http.NewRequestWithContext(ctx, "POST", c.BaseURL+"/createTask", bytes.NewReader(bs))
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	var out struct {
		ErrorID int    `json:"errorId"`
		TaskID  string `json:"taskId"`
		Error   string `json:"errorDescription"`
	}
	b, _ := io.ReadAll(resp.Body)
	if err := json.Unmarshal(b, &out); err != nil {
		return "", fmt.Errorf("createTask decode error: %v", err)
	}
	if out.ErrorID != 0 {
		return "", fmt.Errorf("createTask error: %s", out.Error)
	}
	return out.TaskID, nil
}

func (c *SolverifyClient) GetTaskResult(ctx context.Context, taskID string) (string, string, error) {
	body := map[string]any{"clientKey": c.ClientKey, "taskId": taskID}
	bs, _ := json.Marshal(body)
	req, _ := http.NewRequestWithContext(ctx, "POST", c.BaseURL+"/getTaskResult", bytes.NewReader(bs))
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()
	var out struct {
		Status   string                 `json:"status"`
		Solution map[string]interface{} `json:"solution"`
		ErrorID  int                    `json:"errorId"`
		ErrorMsg string                 `json:"errorDescription"`
	}
	b, _ := io.ReadAll(resp.Body)
	if err := json.Unmarshal(b, &out); err != nil {
		return "", "", fmt.Errorf("getTaskResult decode error: %v", err)
	}
	if out.ErrorID != 0 {
		return "error", "", fmt.Errorf("API error %d: %s", out.ErrorID, out.ErrorMsg)
	}
	if (out.Status == "ready" || out.Status == "completed") && out.Solution != nil {
		for _, k := range []string{"token", "value"} {
			if v, ok := out.Solution[k]; ok {
				if s := fmt.Sprintf("%v", v); s != "" {
					return out.Status, s, nil
				}
			}
		}
	}
	return out.Status, "", nil
}

func (c *SolverifyClient) SolveTurnstile(siteURL, siteKey string, maxAttempts int, timeoutPerTask time.Duration, userAgent string) (string, error) {
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		ctx, cancel := context.WithTimeout(context.Background(), timeoutPerTask)
		taskID, err := c.CreateTurnstileTask(ctx, siteURL, siteKey, userAgent)
		if err != nil {
			cancel()
			time.Sleep(time.Duration(math.Min(5, float64(attempt))) * time.Second)
			continue
		}
		pollInterval := 2 * time.Second
		maxPolls := int(timeoutPerTask / pollInterval)
		for p := 0; p < maxPolls; p++ {
			time.Sleep(pollInterval)
			status, token, err := c.GetTaskResult(ctx, taskID)
			if err != nil {
				continue
			}
			if (status == "ready" || status == "completed") && token != "" {
				cancel()
				return token, nil
			}
		}
		cancel()
		time.Sleep(3 * time.Second)
	}
	return "", fmt.Errorf("all turnstile solve attempts failed")
}

// Utility functions
func generateDeviceID(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func randInt(n int) int {
	b := make([]byte, 1)
	rand.Read(b)
	return int(b[0]) % n
}

func GenerateRealisticFingerprint() Fingerprint {
	devices := []struct {
		brand   string
		model   string
		version string
	}{
		{"Apple", "iPhone 15 Pro Max", "17.6.1"},
		{"Apple", "iPhone 15 Pro", "17.6.1"},
		{"Apple", "iPhone 14 Pro Max", "17.4.1"},
		{"Samsung", "SM-S918B", "14"},
		{"Samsung", "SM-S916B", "14"},
		{"Google", "Pixel 8 Pro", "14"},
		{"Google", "Pixel 7 Pro", "14"},
		{"Xiaomi", "2211133C", "14"},
		{"OnePlus", "CPH2583", "14"},
		{"Oppo", "CPH2525", "14"},
	}

	d := devices[randInt(len(devices))]
	deviceID := generateDeviceID(16)
	chromeVer := 120 + randInt(5)
	webkitVer := 537 + randInt(10)

	return Fingerprint{
		DeviceBrand:   d.brand,
		DeviceModel:   d.model,
		OSVersion:     d.version,
		DeviceID:      deviceID,
		UserAgent:     fmt.Sprintf("Mozilla/5.0 (Linux; Android %s; %s) AppleWebKit/%d.36 (KHTML, like Gecko) Chrome/%d.0.0.0 Mobile Safari/%d.36", d.version, d.model, webkitVer, chromeVer, webkitVer),
		AppVersion:    "1.5.8.5",
		SecCHUA:       fmt.Sprintf("\"Chromium\";v=\"%d\", \"Google Chrome\";v=\"%d\"", chromeVer, chromeVer),
		SecCHMobile:   "?1",
		SecCHPlatform: "\"Android\"",
		Timezone:      "Asia/Manila",
		Language:      "en-US",
	}
}

func makeClientWithProxy(proxyStr string) (*http.Client, error) {
	if proxyStr == "" {
		return &http.Client{Timeout: DefaultTimeout}, nil
	}
	proxyStr = strings.TrimPrefix(proxyStr, "http://")
	proxyStr = strings.TrimPrefix(proxyStr, "https://")
	proxyURL, err := url.Parse("http://" + proxyStr)
	if err != nil {
		return nil, fmt.Errorf("invalid proxy format: %v", err)
	}
	transport := &http.Transport{Proxy: http.ProxyURL(proxyURL)}
	return &http.Client{Timeout: DefaultTimeout, Transport: transport}, nil
}

type zstdReadCloser struct {
	*zstd.Decoder
}

func (z *zstdReadCloser) Close() error {
	z.Decoder.Close()
	return nil
}

func decodeResponseBody(resp *http.Response) ([]byte, error) {
	enc := strings.ToLower(resp.Header.Get("Content-Encoding"))
	var reader io.ReadCloser
	var err error

	switch enc {
	case "gzip":
		reader, err = gzip.NewReader(resp.Body)
		if err != nil {
			return nil, err
		}
		defer reader.Close()
	case "br":
		reader = io.NopCloser(brotli.NewReader(resp.Body))
		defer reader.Close()
	case "zstd", "zst":
		dec, derr := zstd.NewReader(resp.Body)
		if derr != nil {
			return nil, derr
		}
		reader = &zstdReadCloser{dec}
		defer reader.Close()
	default:
		raw, _ := io.ReadAll(resp.Body)
		if len(raw) >= 4 && raw[0] == 0x28 && raw[1] == 0xB5 && raw[2] == 0x2F && raw[3] == 0xFD {
			dec, derr := zstd.NewReader(bytes.NewReader(raw))
			if derr == nil {
				defer dec.Close()
				out, rerr := io.ReadAll(dec)
				if rerr == nil {
					return out, nil
				}
			}
			return raw, nil
		}
		return raw, nil
	}

	out, err := io.ReadAll(reader)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func postFormJSON(client *http.Client, urlStr string, headers map[string]string, form url.Values) (map[string]interface{}, int, error) {
	reqBody := strings.NewReader(form.Encode())
	req, _ := http.NewRequest("POST", urlStr, reqBody)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for k, v := range headers {
		if v != "" {
			req.Header.Set(k, v)
		}
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	body, err := decodeResponseBody(resp)
	if err != nil {
		return nil, resp.StatusCode, err
	}
	var out map[string]interface{}
	if err := json.Unmarshal(body, &out); err != nil {
		return map[string]interface{}{"raw": string(body)}, resp.StatusCode, nil
	}
	return out, resp.StatusCode, nil
}

// Place this after Part 2 and before Part 4

func checkBalance(client *http.Client, bearerToken, suid string) (float64, error) {
	headers := map[string]string{
		"token":      bearerToken,
		"suid":       suid,
		"User-Agent": "Mozilla/5.0",
	}
	payload := map[string]any{"token": bearerToken, "action": "/common/api/jili/backhall"}
	bs, _ := json.Marshal(payload)
	req, _ := http.NewRequest("POST", BackhallEndpoint, bytes.NewReader(bs))
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	body, _ := decodeResponseBody(resp)
	var out map[string]interface{}
	json.Unmarshal(body, &out)
	if data, ok := out["data"].(map[string]interface{}); ok {
		if b, ok := data["balance"].(float64); ok {
			return b / 100.0, nil
		}
	}
	return 0, fmt.Errorf("balance not found")
}

func setPassword(client *http.Client, phone, password, bearerToken, suid, cfToken string) error {
	hasher := md5.New()
	hasher.Write([]byte(password))
	hashedPassword := hex.EncodeToString(hasher.Sum(nil))

	headers := map[string]string{
		"Accept":          "application/json, text/plain, */*",
		"Accept-Encoding": "gzip, deflate, br, zstd",
		"Accept-Language": "en-US,en;q=0.9",
		"appversion":      "2.3.0.2",
		"cf-token":        cfToken,
		"token":           bearerToken,
		"suid":            suid,
		"Connection":      "keep-alive",
		"Content-Type":    "application/x-www-form-urlencoded",
		"Host":            "io.nustargame.com",
		"Origin":          "https://nustargame.ph",
		"Referer":         "https://nustargame.ph/",
		"Sec-Fetch-Dest":  "empty",
		"Sec-Fetch-Mode":  "cors",
		"Sec-Fetch-Site":  "cross-site",
		"User-Agent":      "Mozilla/5.0",
		"source":          "Vue",
		"terminal":        "128",
		"version":         "2.3.0.2",
	}

	form := url.Values{
		"action":         {"/common/api/set/phone/passwd"},
		"token":          {bearerToken},
		"phone":          {phone},
		"telephone_code": {"+63"},
		"password":       {hashedPassword},
		"upd_column":     {"password"},
	}

	resp, status, err := postFormJSON(client, SetPasswordEndpoint, headers, form)
	if err != nil {
		return fmt.Errorf("set password request failed: %v", err)
	}

	if DebugMode {
		log.Printf("Set password response (status %d): %+v", status, resp)
		log.Printf("Set password form data: %+v", form)
	}

	if code, ok := resp["code"].(float64); ok && code == 200 {
		return nil
	}

	if msg, ok := resp["msg"].(string); ok {
		if strings.Contains(strings.ToLower(msg), "already") || strings.Contains(strings.ToLower(msg), "success") {
			return nil
		}
		return fmt.Errorf("password set failed: %s", msg)
	}

	return fmt.Errorf("password set failed with status %d", status)
}

func getOrCreateUser(chatID int64) *UserData {
	usersMutex.Lock()
	defer usersMutex.Unlock()

	if user, exists := users[chatID]; exists {
		user.LastUsed = time.Now()
		return user
	}

	user := &UserData{
		ChatID:   chatID,
		Credits:  0,
		LastUsed: time.Now(),
		IsAdmin:  chatID == botConfig.AdminChatID,
	}
	users[chatID] = user
	saveUsers()
	return user
}

func addCredits(chatID int64, amount int) {
	usersMutex.Lock()
	defer usersMutex.Unlock()

	user := users[chatID]
	if user == nil {
		user = &UserData{ChatID: chatID}
		users[chatID] = user
	}
	user.Credits += amount
	saveUsers()
}

func deductCredits(chatID int64, amount int) bool {
	usersMutex.Lock()
	defer usersMutex.Unlock()

	user := users[chatID]
	if user == nil || user.Credits < amount {
		return false
	}
	user.Credits -= amount
	saveUsers()
	return true
}

func saveUsers() {
	data, err := json.MarshalIndent(users, "", "  ")
	if err != nil {
		log.Printf("Failed to marshal users: %v", err)
		return
	}
	if err := os.WriteFile("users.json", data, 0644); err != nil {
		log.Printf("Failed to save users: %v", err)
	}
}

func loadUsers() error {
	data, err := os.ReadFile("users.json")
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}

	var loadedUsers map[string]*UserData
	if err := json.Unmarshal(data, &loadedUsers); err != nil {
		return err
	}

	usersMutex.Lock()
	defer usersMutex.Unlock()

	for k, v := range loadedUsers {
		chatID, _ := strconv.ParseInt(k, 10, 64)
		users[chatID] = v
	}

	return nil
}

func getSession(chatID int64) *UserSession {
	sessionMutex.Lock()
	defer sessionMutex.Unlock()
	if session, exists := sessions[chatID]; exists {
		session.LastActivity = time.Now()
		return session
	}
	session := &UserSession{
		ChatID:       chatID,
		State:        StateIdle,
		LastActivity: time.Now(),
		IsAdmin:      chatID == botConfig.AdminChatID,
	}
	sessions[chatID] = session
	return session
}

func clearSession(chatID int64) {
	sessionMutex.Lock()
	defer sessionMutex.Unlock()
	delete(sessions, chatID)
}

// Bot handlers
func handleStart(bot *tgbotapi.BotAPI, message *tgbotapi.Message) {
	session := getSession(message.Chat.ID)
	user := getOrCreateUser(message.Chat.ID)

	keyboard := tgbotapi.NewReplyKeyboard(
		tgbotapi.NewKeyboardButtonRow(
			tgbotapi.NewKeyboardButton("🚀 Create Accounts"),
			tgbotapi.NewKeyboardButton("💳 My Credits"),
		),
		tgbotapi.NewKeyboardButtonRow(
			tgbotapi.NewKeyboardButton("🔐 Set Default Password"),
			tgbotapi.NewKeyboardButton("ℹ️ Help"),
		),
	)

	if session.IsAdmin {
		keyboard.Keyboard = append(keyboard.Keyboard,
			tgbotapi.NewKeyboardButtonRow(
				tgbotapi.NewKeyboardButton("⚙️ Admin Panel"),
			),
		)
	}

	msg := tgbotapi.NewMessage(message.Chat.ID,
		fmt.Sprintf("👋 *Welcome to NuStar Account Creator Bot!*\n\n"+
			"🆔 Your User ID: `%d`\n"+
			"💰 Your Credits: *%d*\n"+
			"📊 Accounts Created: *%d*\n\n"+
			"Click '🚀 Create Accounts' to begin!\n"+
			"💡 Cost: %d credit per account",
			message.Chat.ID, user.Credits, user.TotalCreated, CreditsPerAccount))
	msg.ParseMode = "Markdown"
	msg.ReplyMarkup = keyboard
	bot.Send(msg)
}
func handleMyCredits(bot *tgbotapi.BotAPI, chatID int64) {
	user := getOrCreateUser(chatID)

	msg := tgbotapi.NewMessage(chatID,
		fmt.Sprintf("💳 *Your Account Stats*\n\n"+
			"💰 Available Credits: *%d*\n"+
			"📊 Total Accounts Created: *%d*\n"+
			"⏰ Last Used: %s\n\n"+
			"💡 Each account costs %d credit to create\n"+
			"Contact admin to purchase more credits!",
			user.Credits,
			user.TotalCreated,
			user.LastUsed.Format("Jan 02, 2006 15:04"),
			CreditsPerAccount))
	msg.ParseMode = "Markdown"
	bot.Send(msg)
}

func handleSetDefaultPassword(bot *tgbotapi.BotAPI, chatID int64) {
	session := getSession(chatID)
	user := getOrCreateUser(chatID)

	currentPass := "Not set"
	if user.DefaultPassword != "" {
		currentPass = "********"
	}

	session.State = StateSettingDefaultPassword
	msg := tgbotapi.NewMessage(chatID,
		fmt.Sprintf("🔐 *Set Default Password*\n\n"+
			"Current: `%s`\n\n"+
			"Send your new default password:\n"+
			"(This will be used for all accounts unless you choose otherwise)",
			currentPass))
	msg.ParseMode = "Markdown"
	bot.Send(msg)
}

func handleDefaultPasswordInput(bot *tgbotapi.BotAPI, chatID int64, password string) {
	session := getSession(chatID)
	user := getOrCreateUser(chatID)

	user.DefaultPassword = password
	session.State = StateIdle
	saveUsers()

	msg := tgbotapi.NewMessage(chatID,
		"✅ Default password saved!\n\n"+
			"You can now create accounts without entering a password each time.")
	bot.Send(msg)
}

func handleCreateAccounts(bot *tgbotapi.BotAPI, chatID int64) {
	session := getSession(chatID)
	user := getOrCreateUser(chatID)

	if user.Credits < CreditsPerAccount {
		msg := tgbotapi.NewMessage(chatID,
			fmt.Sprintf("❌ Insufficient credits!\n\n"+
				"You have: *%d* credits\n"+
				"Required: *%d* credit per account\n\n"+
				"Contact admin to purchase more credits.",
				user.Credits, CreditsPerAccount))
		msg.ParseMode = "Markdown"
		bot.Send(msg)
		return
	}

	session.CreatedAccounts = []string{}

	// Check if user has default password
	if user.DefaultPassword != "" {
		keyboard := tgbotapi.NewInlineKeyboardMarkup(
			tgbotapi.NewInlineKeyboardRow(
				tgbotapi.NewInlineKeyboardButtonData("✅ Use Default Password", "use_default_pass"),
				tgbotapi.NewInlineKeyboardButtonData("🔐 Enter New Password", "use_custom_pass"),
			),
		)

		msg := tgbotapi.NewMessage(chatID, "🔑 Password Selection\n\nDo you want to use your default password?")
		msg.ReplyMarkup = keyboard
		bot.Send(msg)
	} else {
		session.State = StateAwaitingPassword
		session.UseDefaultPass = false
		msg := tgbotapi.NewMessage(chatID, "🔑 Please enter the password for all accounts:")
		bot.Send(msg)
	}
}
func handlePassword(bot *tgbotapi.BotAPI, chatID int64, password string) {
	session := getSession(chatID)
	user := getOrCreateUser(chatID)

	if session.UseDefaultPass && user.DefaultPassword != "" {
		session.Password = user.DefaultPassword
	} else {
		session.Password = password
	}

	session.State = StateAwaitingCount

	maxAccounts := user.Credits / CreditsPerAccount
	if maxAccounts > 999 {
		maxAccounts = 999
	}
	msg := tgbotapi.NewMessage(chatID,
		fmt.Sprintf("📊 How many accounts do you want to create? (1-%d)\n\n"+
			"💰 Your credits: %d\n"+
			"💡 Cost: %d credit per account",
			maxAccounts, user.Credits, CreditsPerAccount))
	bot.Send(msg)
}

func handleCount(bot *tgbotapi.BotAPI, chatID int64, countStr string) {
	session := getSession(chatID)
	user := getOrCreateUser(chatID)

	count, err := strconv.Atoi(countStr)
	if err != nil || count < 1 {
		msg := tgbotapi.NewMessage(chatID, "❌ Invalid number. Please enter a valid number.")
		bot.Send(msg)
		return
	}

	maxAccounts := user.Credits / CreditsPerAccount
	if count > maxAccounts {
		msg := tgbotapi.NewMessage(chatID,
			fmt.Sprintf("❌ Insufficient credits!\n\n"+
				"You requested: %d accounts (%d credits)\n"+
				"You have: %d credits\n"+
				"Max you can create: %d accounts",
				count, count*CreditsPerAccount, user.Credits, maxAccounts))
		bot.Send(msg)
		return
	}
	if count > 999 {
		msg := tgbotapi.NewMessage(chatID, "❌ Maximum 999 accounts per batch. Please enter a number between 1 and 999.")
		bot.Send(msg)
		return
	}

	session.AccountCount = count
	session.CurrentAccount = 1
	session.State = StateAwaitingPhone

	msg := tgbotapi.NewMessage(chatID,
		fmt.Sprintf("📱 Account 1/%d\n\n"+
			"Enter phone number (9xxxxxxxxx):\n"+
			"💰 Cost: %d credits for %d accounts",
			count, count*CreditsPerAccount, count))
	bot.Send(msg)
}

func handlePhone(bot *tgbotapi.BotAPI, chatID int64, phone string) {
	session := getSession(chatID)
	user := getOrCreateUser(chatID)

	// Validate phone
	matched, _ := regexp.MatchString(`^9\d{9}$`, phone)
	if !matched {
		msg := tgbotapi.NewMessage(chatID, "❌ Invalid phone format. Please use format: 9xxxxxxxxx")
		bot.Send(msg)
		return
	}

	// Deduct credits for first account only
	if session.CurrentAccount == 1 {
		totalCredits := session.AccountCount * CreditsPerAccount
		if !deductCredits(chatID, totalCredits) {
			msg := tgbotapi.NewMessage(chatID,
				fmt.Sprintf("❌ Insufficient credits!\n\nRequired: %d credits\nYou have: %d credits",
					totalCredits, user.Credits))
			bot.Send(msg)
			clearSession(chatID)
			return
		}
		msg := tgbotapi.NewMessage(chatID,
			fmt.Sprintf("✅ %d credits deducted\n💰 Remaining: %d credits",
				totalCredits, user.Credits-totalCredits))
		bot.Send(msg)
	}

	session.Phone = phone
	session.State = StateProcessing

	// Send SMS
	go processSMS(bot, session)
}

func handleHelp(bot *tgbotapi.BotAPI, chatID int64) {
	user := getOrCreateUser(chatID)

	helpText := fmt.Sprintf(`📖 *Help Guide*

*Your Account:*
💰 Credits: %d
📊 Total Created: %d accounts

*How to use:*
1️⃣ Set a default password (optional)
2️⃣ Click '🚀 Create Accounts'
3️⃣ Choose password option
4️⃣ Enter number of accounts
5️⃣ For each account:
   • Enter phone (9xxxxxxxxx)
   • Wait for SMS
   • Enter SMS code

*Features:*
✅ Credits system
✅ Default password
✅ Auto captcha solving
✅ Balance checking
✅ Account saving

*Cost:*
💡 %d credit per account

*Support:*
Contact @YourAdmin for credits`,
		user.Credits, user.TotalCreated, CreditsPerAccount)

	msg := tgbotapi.NewMessage(chatID, helpText)
	msg.ParseMode = "Markdown"
	bot.Send(msg)
}
func processSMS(bot *tgbotapi.BotAPI, session *UserSession) {
	msg := tgbotapi.NewMessage(session.ChatID, "🔄 Solving captcha...")
	bot.Send(msg)

	// Generate fingerprint
	session.Fingerprint = GenerateRealisticFingerprint()

	// Solve captcha
	solver := NewSolverifyClient("https://solver.solverify.net", botConfig.APIKey)
	token, err := solver.SolveTurnstile(TurnstileSiteURL, TurnstileSiteKey, 3, 90*time.Second, session.Fingerprint.UserAgent)
	if err != nil {
		msg := tgbotapi.NewMessage(session.ChatID, fmt.Sprintf("❌ Captcha failed: %v", err))
		bot.Send(msg)
		session.State = StateAwaitingPhone
		return
	}

	session.TurnstileToken = token

	msg = tgbotapi.NewMessage(session.ChatID, "✅ Captcha solved\n📧 Sending SMS code...")
	bot.Send(msg)

	// Create HTTP client
	client, err := makeClientWithProxy(botConfig.ProxyURL)
	if err != nil {
		msg := tgbotapi.NewMessage(session.ChatID, fmt.Sprintf("❌ Proxy error: %v", err))
		bot.Send(msg)
		session.State = StateAwaitingPhone
		return
	}

	// Send SMS
	headers := map[string]string{
		"Accept":             "application/json, text/plain, */*",
		"Accept-Encoding":    "gzip, deflate, br, zstd",
		"Accept-Language":    "en-US,en;q=0.9",
		"appversion":         "2.3.0.2",
		"cf-scene":           "SCENE_GET_CODE",
		"cf-token":           token,
		"Connection":         "keep-alive",
		"Content-Type":       "application/x-www-form-urlencoded",
		"Host":               "io.nustargame.com",
		"Origin":             "https://nustargame.ph",
		"Referer":            "https://nustargame.ph/",
		"sec-ch-ua":          session.Fingerprint.SecCHUA,
		"sec-ch-ua-mobile":   session.Fingerprint.SecCHMobile,
		"sec-ch-ua-platform": session.Fingerprint.SecCHPlatform,
		"Sec-Fetch-Dest":     "empty",
		"Sec-Fetch-Mode":     "cors",
		"Sec-Fetch-Site":     "cross-site",
		"source":             "Vue",
		"terminal":           "128",
		"User-Agent":         session.Fingerprint.UserAgent,
		"version":            "2.3.0.2",
	}

	smsForm := url.Values{
		"action":        {"/common/api/sms/send/short/msg"},
		"phone":         {session.Phone},
		"telephoneCode": {"+63"},
		"type":          {"1"},
	}

	resp, status, err := postFormJSON(client, SMSEndpoint, headers, smsForm)
	if err != nil {
		msg := tgbotapi.NewMessage(session.ChatID, fmt.Sprintf("❌ SMS request failed: %v", err))
		bot.Send(msg)
		session.State = StateAwaitingPhone
		return
	}

	if DebugMode {
		log.Printf("SMS Response Status: %d", status)
		log.Printf("SMS Response Body: %+v", resp)
	}

	success := false
	if status == 200 {
		if code, ok := resp["code"].(float64); ok {
			if code == 200 {
				success = true
			}
		} else {
			success = true
		}
	}

	if success {
		msg = tgbotapi.NewMessage(session.ChatID, "✅ SMS sent!\n\n📢 Please enter the SMS code you received:")
		bot.Send(msg)
		session.State = StateAwaitingSMS
	} else {
		errorMsg := "Unknown error"
		if msg, ok := resp["msg"].(string); ok {
			errorMsg = msg
		} else if message, ok := resp["message"].(string); ok {
			errorMsg = message
		}
		msg := tgbotapi.NewMessage(session.ChatID, fmt.Sprintf("❌ SMS failed: %s\n\nPlease try again.", errorMsg))
		bot.Send(msg)
		session.State = StateAwaitingPhone
	}
}

func handleSMS(bot *tgbotapi.BotAPI, chatID int64, smsCode string) {
	session := getSession(chatID)
	session.SMSCode = smsCode
	session.State = StateProcessing

	go processLogin(bot, session)
}

func processLogin(bot *tgbotapi.BotAPI, session *UserSession) {
	msg := tgbotapi.NewMessage(session.ChatID, "🔄 Solving login captcha...")
	bot.Send(msg)

	solver := NewSolverifyClient("https://solver.solverify.net", botConfig.APIKey)
	loginToken, err := solver.SolveTurnstile(TurnstileSiteURL, TurnstileSiteKey, 3, 90*time.Second, session.Fingerprint.UserAgent)
	if err != nil {
		loginToken = session.TurnstileToken
		log.Printf("Warning: Login captcha solve failed, using SMS token: %v", err)
	} else {
		msg = tgbotapi.NewMessage(session.ChatID, "✅ Login captcha solved")
		bot.Send(msg)
	}

	msg = tgbotapi.NewMessage(session.ChatID, "🔓 Logging in...")
	bot.Send(msg)

	client, _ := makeClientWithProxy(botConfig.ProxyURL)

	headers := map[string]string{
		"Accept":             "application/json, text/plain, */*",
		"Accept-Encoding":    "gzip, deflate, br, zstd",
		"Accept-Language":    "en-US,en;q=0.9",
		"appversion":         "2.3.0.2",
		"cf-scene":           "SCENE_LOGIN",
		"cf-token":           loginToken,
		"Connection":         "keep-alive",
		"Content-Type":       "application/x-www-form-urlencoded",
		"Host":               "io.nustargame.com",
		"Origin":             "https://nustargame.ph",
		"Referer":            "https://nustargame.ph/",
		"sec-ch-ua":          session.Fingerprint.SecCHUA,
		"sec-ch-ua-mobile":   session.Fingerprint.SecCHMobile,
		"sec-ch-ua-platform": session.Fingerprint.SecCHPlatform,
		"Sec-Fetch-Dest":     "empty",
		"Sec-Fetch-Mode":     "cors",
		"Sec-Fetch-Site":     "cross-site",
		"source":             "Vue",
		"terminal":           "128",
		"User-Agent":         session.Fingerprint.UserAgent,
		"version":            "2.3.0.2",
	}

	loginForm := url.Values{
		"action":               {"/common/api/player/login"},
		"appPackageName":       {"com.playmate.playzone"},
		"deviceId":             {session.Fingerprint.DeviceID},
		"deviceModel":          {"WEB"},
		"deviceVersion":        {"WEB"},
		"appVersion":           {"2.3.0.2"},
		"sysTimezone":          {"Asia/Manila"},
		"sysLanguage":          {"en-US"},
		"telephoneCode":        {"+63"},
		"buds":                 {"64"},
		"appChannel":           {"Web"},
		"registration_channel": {"Web"},
		"isNative":             {"0"},
		"source":               {"4"},
		"gclid":                {""},
		"gbraid":               {""},
		"wbraid":               {""},
		"login_type":           {"phone"},
		"phone":                {session.Phone},
		"verifyCode":           {session.SMSCode},
	}

	var respLogin map[string]interface{}
	var loginErr error

	for attempt := 1; attempt <= 3; attempt++ {
		if attempt > 1 {
			msg := tgbotapi.NewMessage(session.ChatID, fmt.Sprintf("🔄 Login attempt %d/3...", attempt))
			bot.Send(msg)
			time.Sleep(2 * time.Second)
		}

		respLogin, _, loginErr = postFormJSON(client, LoginEndpoint, headers, loginForm)
		if loginErr == nil {
			break
		}

		if DebugMode {
			log.Printf("Login attempt %d failed: %v", attempt, loginErr)
		}
	}

	if loginErr != nil {
		msg := tgbotapi.NewMessage(session.ChatID, fmt.Sprintf("❌ Login failed: %v", loginErr))
		bot.Send(msg)
		session.State = StateAwaitingPhone
		return
	}

	if DebugMode {
		log.Printf("Login response: %+v", respLogin)
	}

	if code, ok := respLogin["code"].(float64); ok && code != 200 {
		errMsg := "Unknown error"
		if msg, ok := respLogin["msg"].(string); ok {
			errMsg = msg
		} else if message, ok := respLogin["message"].(string); ok {
			errMsg = message
		}
		msg := tgbotapi.NewMessage(session.ChatID,
			fmt.Sprintf("❌ Login failed: %s\n\nThe SMS code may have expired. Please request a new code.", errMsg))
		bot.Send(msg)
		session.State = StateAwaitingPhone
		return
	}

	var token, suid string
	if data, ok := respLogin["data"].(map[string]interface{}); ok {
		if t, ok := data["token"].(string); ok {
			token = t
		}
		if userInfo, ok := data["user_info"].(map[string]interface{}); ok {
			if s, ok := userInfo["suid"].(string); ok {
				suid = s
			}
		}
	}

	if token == "" {
		msg := tgbotapi.NewMessage(session.ChatID, "❌ Login failed - invalid SMS code or code expired\n\nPlease start over and request a new SMS code.")
		bot.Send(msg)
		session.State = StateAwaitingPhone
		return
	}

	msg = tgbotapi.NewMessage(session.ChatID, "✅ Login successful\n🔐 Setting password...")
	bot.Send(msg)

	// Set password with retry logic
	var setPassErr error
	for attempt := 1; attempt <= 3; attempt++ {
		setPassErr = setPassword(client, session.Phone, session.Password, token, suid, loginToken)
		if setPassErr == nil {
			break
		}
		if strings.Contains(setPassErr.Error(), "already set") {
			setPassErr = nil
			break
		}
		if attempt < 3 {
			time.Sleep(2 * time.Second)
		}
	}

	if setPassErr != nil {
		log.Printf("Password set error after retries: %v", setPassErr)
		msg = tgbotapi.NewMessage(session.ChatID,
			fmt.Sprintf("⚠️ Warning: Password may not be set correctly\nError: %v\n\nContinuing...", setPassErr))
		bot.Send(msg)
	} else {
		msg = tgbotapi.NewMessage(session.ChatID, "✅ Password set successfully")
		bot.Send(msg)
	}

	time.Sleep(2 * time.Second)

	// Check balance
	balance, _ := checkBalance(client, token, suid)

	accountInfo := fmt.Sprintf("%s|%s|₱%.2f", session.Phone, session.Password, balance)
	session.CreatedAccounts = append(session.CreatedAccounts, accountInfo)

	// Update user stats
	user := getOrCreateUser(session.ChatID)
	usersMutex.Lock()
	user.TotalCreated++
	usersMutex.Unlock()
	saveUsers()

	// Save to file
	f, _ := os.OpenFile("accounts.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if f != nil {
		f.WriteString(accountInfo + "\n")
		f.Close()
	}

	msg = tgbotapi.NewMessage(session.ChatID,
		fmt.Sprintf("✅ Account Created!\n\n"+
			"📱 Phone: %s\n"+
			"🔐 Password: %s\n"+
			"💵 Balance: ₱%.2f", session.Phone, session.Password, balance))
	bot.Send(msg)

	// Check if more accounts needed
	session.CurrentAccount++
	if session.CurrentAccount <= session.AccountCount {
		time.Sleep(3 * time.Second)
		session.State = StateAwaitingPhone
		msg = tgbotapi.NewMessage(session.ChatID,
			fmt.Sprintf("📱 Account %d/%d\n\nEnter phone number (9xxxxxxxxx):",
				session.CurrentAccount, session.AccountCount))
		bot.Send(msg)
	} else {
		// All done
		summary := fmt.Sprintf("✨ *All Accounts Created!*\n\n"+
			"Total: %d accounts\n"+
			"💰 Credits remaining: %d\n\n"+
			"*Account Details:*\n", len(session.CreatedAccounts), user.Credits)
		for i, acc := range session.CreatedAccounts {
			summary += fmt.Sprintf("%d. `%s`\n", i+1, acc)
		}
		msg = tgbotapi.NewMessage(session.ChatID, summary)
		msg.ParseMode = "Markdown"
		bot.Send(msg)
		clearSession(session.ChatID)
	}
}
func handleAdminPanel(bot *tgbotapi.BotAPI, chatID int64) {
	session := getSession(chatID)
	if !session.IsAdmin {
		msg := tgbotapi.NewMessage(chatID, "❌ You don't have admin access")
		bot.Send(msg)
		return
	}

	keyboard := tgbotapi.NewInlineKeyboardMarkup(
		tgbotapi.NewInlineKeyboardRow(
			tgbotapi.NewInlineKeyboardButtonData("📊 Statistics", "admin_stats"),
			tgbotapi.NewInlineKeyboardButtonData("👥 Users", "admin_users"),
		),
		tgbotapi.NewInlineKeyboardRow(
			tgbotapi.NewInlineKeyboardButtonData("💳 Add Credits", "admin_add_credits"),
			tgbotapi.NewInlineKeyboardButtonData("🌐 Set Proxy", "admin_proxy"),
		),
		tgbotapi.NewInlineKeyboardRow(
			tgbotapi.NewInlineKeyboardButtonData("📜 View Logs", "admin_logs"),
			tgbotapi.NewInlineKeyboardButtonData("📢 Broadcast", "admin_broadcast"),
		),
	)

	msg := tgbotapi.NewMessage(chatID, "⚙️ *Admin Panel*\n\nSelect an option:")
	msg.ParseMode = "Markdown"
	msg.ReplyMarkup = keyboard
	bot.Send(msg)
}

func handleAdminAddCredits(bot *tgbotapi.BotAPI, chatID int64) {
	session := getSession(chatID)
	session.State = StateAdminAwaitingChatID

	msg := tgbotapi.NewMessage(chatID, "💳 *Add Credits*\n\nSend the user's Chat ID:")
	msg.ParseMode = "Markdown"
	bot.Send(msg)
}

func handleAdminChatIDInput(bot *tgbotapi.BotAPI, chatID int64, input string) {
	session := getSession(chatID)

	targetChatID, err := strconv.ParseInt(input, 10, 64)
	if err != nil {
		msg := tgbotapi.NewMessage(chatID, "❌ Invalid Chat ID. Please enter a valid number.")
		bot.Send(msg)
		return
	}

	session.State = StateAdminAwaitingCredits
	session.Phone = input // Store chat ID temporarily

	msg := tgbotapi.NewMessage(chatID,
		fmt.Sprintf("💳 Adding credits to Chat ID: `%d`\n\nHow many credits to add?", targetChatID))
	msg.ParseMode = "Markdown"
	bot.Send(msg)
}

func handleAdminCreditsInput(bot *tgbotapi.BotAPI, chatID int64, input string) {
	session := getSession(chatID)

	credits, err := strconv.Atoi(input)
	if err != nil || credits < 1 {
		msg := tgbotapi.NewMessage(chatID, "❌ Invalid amount. Please enter a positive number.")
		bot.Send(msg)
		return
	}

	targetChatID, _ := strconv.ParseInt(session.Phone, 10, 64)

	// Create user if doesn't exist
	targetUser := getOrCreateUser(targetChatID)
	addCredits(targetChatID, credits)

	session.State = StateIdle

	msg := tgbotapi.NewMessage(chatID,
		fmt.Sprintf("✅ Successfully added %d credits to Chat ID: `%d`\n\n"+
			"New balance: %d credits", credits, targetChatID, targetUser.Credits+credits))
	msg.ParseMode = "Markdown"
	bot.Send(msg)

	// Notify user
	notifyMsg := tgbotapi.NewMessage(targetChatID,
		fmt.Sprintf("🎉 You received %d credits!\n\n💰 Your new balance: %d credits",
			credits, targetUser.Credits+credits))
	bot.Send(notifyMsg)
}

func handleAdminStats(bot *tgbotapi.BotAPI, chatID int64) {
	sessionMutex.RLock()
	activeUsers := len(sessions)
	sessionMutex.RUnlock()

	usersMutex.RLock()
	totalUsers := len(users)
	totalCredits := 0
	totalAccounts := 0
	for _, user := range users {
		totalCredits += user.Credits
		totalAccounts += user.TotalCreated
	}
	usersMutex.RUnlock()

	statsText := fmt.Sprintf(`📊 *Bot Statistics*

👥 Total Users: %d
🔄 Active Sessions: %d
💳 Total Credits: %d
📱 Total Accounts: %d
🌐 Proxy: %s

*System:*
💻 OS: %s
🐹 Go: %s`,
		totalUsers,
		activeUsers,
		totalCredits,
		totalAccounts,
		func() string {
			if botConfig.ProxyURL != "" {
				return "✅ Enabled"
			}
			return "❌ Disabled"
		}(),
		runtime.GOOS,
		runtime.Version())

	msg := tgbotapi.NewMessage(chatID, statsText)
	msg.ParseMode = "Markdown"
	bot.Send(msg)
}

func handleAdminUsers(bot *tgbotapi.BotAPI, chatID int64) {
	usersMutex.RLock()
	defer usersMutex.RUnlock()

	if len(users) == 0 {
		msg := tgbotapi.NewMessage(chatID, "No users found")
		bot.Send(msg)
		return
	}

	var userList strings.Builder
	userList.WriteString("👥 *All Users:*\n\n")

	for _, user := range users {
		userList.WriteString(fmt.Sprintf("• Chat ID: `%d`\n", user.ChatID))
		userList.WriteString(fmt.Sprintf("  💰 Credits: %d\n", user.Credits))
		userList.WriteString(fmt.Sprintf("  📊 Created: %d\n", user.TotalCreated))
		userList.WriteString(fmt.Sprintf("  ⏰ Last: %s ago\n\n",
			time.Since(user.LastUsed).Round(time.Minute)))
	}

	msg := tgbotapi.NewMessage(chatID, userList.String())
	msg.ParseMode = "Markdown"
	bot.Send(msg)
}

func handleAdminProxyMenu(bot *tgbotapi.BotAPI, chatID int64) {
	keyboard := tgbotapi.NewInlineKeyboardMarkup(
		tgbotapi.NewInlineKeyboardRow(
			tgbotapi.NewInlineKeyboardButtonData("🌐 Set Proxy", "proxy_set"),
			tgbotapi.NewInlineKeyboardButtonData("🧪 Test Proxy", "proxy_test"),
		),
	)

	proxyStatus := "❌ Not configured"
	if botConfig.ProxyURL != "" {
		proxyStatus = fmt.Sprintf("✅ Active: `%s`", botConfig.ProxyURL)
	}

	msg := tgbotapi.NewMessage(chatID,
		fmt.Sprintf("🌐 *Proxy Management*\n\nCurrent: %s\n\nThis proxy is used for ALL users.", proxyStatus))
	msg.ParseMode = "Markdown"
	msg.ReplyMarkup = keyboard
	bot.Send(msg)
}

func handleAdminProxySet(bot *tgbotapi.BotAPI, chatID int64, proxy string) {
	session := getSession(chatID)
	session.State = StateIdle

	if strings.ToLower(proxy) == "none" {
		botConfig.ProxyURL = ""
		saveConfig()
		msg := tgbotapi.NewMessage(chatID, "✅ Proxy disabled for all users")
		bot.Send(msg)
		return
	}

	if !strings.Contains(proxy, ":") {
		msg := tgbotapi.NewMessage(chatID, "❌ Invalid format. Use: ip:port:user:pass")
		bot.Send(msg)
		return
	}

	botConfig.ProxyURL = proxy
	saveConfig()

	msg := tgbotapi.NewMessage(chatID,
		fmt.Sprintf("✅ Proxy set for ALL users:\n`%s`\n\nUse 'Test Proxy' to verify", proxy))
	msg.ParseMode = "Markdown"
	bot.Send(msg)
}

func handleAdminProxyTest(bot *tgbotapi.BotAPI, chatID int64) {
	if botConfig.ProxyURL == "" {
		msg := tgbotapi.NewMessage(chatID, "❌ No proxy configured")
		bot.Send(msg)
		return
	}

	msg := tgbotapi.NewMessage(chatID, "🧪 Testing proxy...")
	bot.Send(msg)

	client, err := makeClientWithProxy(botConfig.ProxyURL)
	if err != nil {
		msg := tgbotapi.NewMessage(chatID, fmt.Sprintf("❌ Proxy error: %v", err))
		bot.Send(msg)
		return
	}

	req, _ := http.NewRequest("GET", "https://api.ipify.org?format=json", nil)
	resp, err := client.Do(req)
	if err != nil {
		msg := tgbotapi.NewMessage(chatID, fmt.Sprintf("❌ Connection failed: %v", err))
		bot.Send(msg)
		return
	}
	defer resp.Body.Close()

	var result map[string]string
	body, _ := io.ReadAll(resp.Body)
	json.Unmarshal(body, &result)

	msg = tgbotapi.NewMessage(chatID,
		fmt.Sprintf("✅ *Proxy Working!*\n\nIP: `%s`\n\nThis proxy is used by all users.", result["ip"]))
	msg.ParseMode = "Markdown"
	bot.Send(msg)
}

func handleAdminLogs(bot *tgbotapi.BotAPI, chatID int64) {
	data, err := os.ReadFile("accounts.txt")
	if err != nil {
		msg := tgbotapi.NewMessage(chatID, "❌ No logs found")
		bot.Send(msg)
		return
	}

	lines := strings.Split(string(data), "\n")
	start := len(lines) - 50
	if start < 0 {
		start = 0
	}

	recentLogs := strings.Join(lines[start:], "\n")

	msg := tgbotapi.NewMessage(chatID,
		fmt.Sprintf("📜 *Recent Accounts (Last 50):*\n\n```\n%s\n```", recentLogs))
	msg.ParseMode = "Markdown"
	bot.Send(msg)
}

func handleAdminBroadcast(bot *tgbotapi.BotAPI, chatID int64) {
	session := getSession(chatID)
	session.State = StateAdminAwaitingBroadcast

	msg := tgbotapi.NewMessage(chatID, "📢 *Broadcast Message*\n\nSend the message you want to broadcast to all users:\n\n⚠️ This will be sent to ALL users!")
	msg.ParseMode = "Markdown"
	bot.Send(msg)
}

func handleAdminBroadcastInput(bot *tgbotapi.BotAPI, chatID int64, message string) {
	session := getSession(chatID)
	session.State = StateIdle

	usersMutex.RLock()
	totalUsers := len(users)
	usersList := make([]int64, 0, totalUsers)
	for uid := range users {
		usersList = append(usersList, uid)
	}
	usersMutex.RUnlock()

	if totalUsers == 0 {
		msg := tgbotapi.NewMessage(chatID, "❌ No users to broadcast to")
		bot.Send(msg)
		return
	}

	confirmMsg := tgbotapi.NewMessage(chatID,
		fmt.Sprintf("📢 Broadcasting to %d users...", totalUsers))
	bot.Send(confirmMsg)

	successCount := 0
	failCount := 0

	for _, userID := range usersList {
		broadcastMsg := tgbotapi.NewMessage(userID, fmt.Sprintf("📢 *Announcement from Admin*\n\n%s", message))
		broadcastMsg.ParseMode = "Markdown"
		_, err := bot.Send(broadcastMsg)
		if err != nil {
			failCount++
			log.Printf("Failed to send broadcast to %d: %v", userID, err)
		} else {
			successCount++
		}
		time.Sleep(100 * time.Millisecond) // Avoid rate limiting
	}

	resultMsg := tgbotapi.NewMessage(chatID,
		fmt.Sprintf("✅ *Broadcast Complete!*\n\n"+
			"✅ Sent: %d\n"+
			"❌ Failed: %d\n"+
			"📊 Total: %d",
			successCount, failCount, totalUsers))
	resultMsg.ParseMode = "Markdown"
	bot.Send(resultMsg)
}

func handleMessage(bot *tgbotapi.BotAPI, message *tgbotapi.Message) {
	if message.Text == "" {
		return
	}

	session := getSession(message.Chat.ID)

	switch message.Text {
	case "/start":
		handleStart(bot, message)
		return
	case "🚀 Create Accounts":
		handleCreateAccounts(bot, message.Chat.ID)
		return
	case "💳 My Credits":
		handleMyCredits(bot, message.Chat.ID)
		return
	case "🔐 Set Default Password":
		handleSetDefaultPassword(bot, message.Chat.ID)
		return
	case "ℹ️ Help":
		handleHelp(bot, message.Chat.ID)
		return
	case "⚙️ Admin Panel":
		handleAdminPanel(bot, message.Chat.ID)
		return
	case "❌ Cancel":
		clearSession(message.Chat.ID)
		msg := tgbotapi.NewMessage(message.Chat.ID, "✅ Operation cancelled")
		bot.Send(msg)
		handleStart(bot, message)
		return
	}

	switch session.State {
	case StateSettingDefaultPassword:
		handleDefaultPasswordInput(bot, message.Chat.ID, message.Text)
	case StateAwaitingPassword:
		handlePassword(bot, message.Chat.ID, message.Text)
	case StateAwaitingCount:
		handleCount(bot, message.Chat.ID, message.Text)
	case StateAwaitingPhone:
		handlePhone(bot, message.Chat.ID, message.Text)
	case StateAwaitingSMS:
		handleSMS(bot, message.Chat.ID, message.Text)
	case StateAdminAwaitingChatID:
		handleAdminChatIDInput(bot, message.Chat.ID, message.Text)
	case StateAdminAwaitingCredits:
		handleAdminCreditsInput(bot, message.Chat.ID, message.Text)
	case StateAdminAwaitingProxy:
		handleAdminProxySet(bot, message.Chat.ID, message.Text)
	case StateAdminAwaitingBroadcast:
		handleAdminBroadcastInput(bot, message.Chat.ID, message.Text)
	default:
		msg := tgbotapi.NewMessage(message.Chat.ID, "Please use the buttons or /start to begin")
		bot.Send(msg)
	}
}

func handleCallbackQuery(bot *tgbotapi.BotAPI, query *tgbotapi.CallbackQuery) {
	callback := tgbotapi.NewCallback(query.ID, "")
	bot.Request(callback)

	session := getSession(query.Message.Chat.ID)

	switch query.Data {
	case "use_default_pass":
		session.UseDefaultPass = true
		session.State = StateAwaitingCount
		handlePassword(bot, query.Message.Chat.ID, "")
	case "use_custom_pass":
		session.UseDefaultPass = false
		session.State = StateAwaitingPassword
		msg := tgbotapi.NewMessage(query.Message.Chat.ID, "🔑 Please enter the password for all accounts:")
		bot.Send(msg)
	case "admin_stats":
		handleAdminStats(bot, query.Message.Chat.ID)
	case "admin_users":
		handleAdminUsers(bot, query.Message.Chat.ID)
	case "admin_add_credits":
		handleAdminAddCredits(bot, query.Message.Chat.ID)
	case "admin_proxy":
		handleAdminProxyMenu(bot, query.Message.Chat.ID)
	case "admin_logs":
		handleAdminLogs(bot, query.Message.Chat.ID)
	case "proxy_set":
		session.State = StateAdminAwaitingProxy
		msg := tgbotapi.NewMessage(query.Message.Chat.ID, "🌐 Send proxy in format: ip:port:user:pass\n\nOr send 'none' to disable proxy")
		bot.Send(msg)
	case "proxy_test":
		handleAdminProxyTest(bot, query.Message.Chat.ID)
	case "admin_broadcast":
		handleAdminBroadcast(bot, query.Message.Chat.ID)
	}
}
