// Package billing talks to Creem, which sells SendScore Pro as merchant of
// record: it takes the card, charges it, handles the tax, and tells the app
// what happened by webhook.
//
// Two rules shape it, both ported from Scratchpad. Creem decides, not the
// app: a subscription's state lives at Creem and the subscriptions table is
// a copy kept by the webhook, so a checkout's return grants nothing. And the
// key decides which world the app is in: a test key (creem_test_) talks to
// Creem's test API and a live key to the live one, derived rather than
// configured beside it, so the two cannot disagree.
package billing

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// TestKeyPrefix starts every Creem test key.
const TestKeyPrefix = "creem_test_"

// SignatureHeader is the header Creem signs each webhook delivery with.
const SignatureHeader = "creem-signature"

// Billing periods.
const (
	Monthly = "monthly"
	Yearly  = "yearly"
)

// Prices, for the pages to say. Creem holds the real ones.
const (
	PriceMonthly = "$9"
	PriceYearly  = "$90"
)

// MinSecretLen is the shortest SENDSCORE_SECRET accepted.
const MinSecretLen = 32

// ErrNotSetUp is returned when billing is missing a setting it needs.
var ErrNotSetUp = errors.New("billing is not set up")

// Config is what billing needs, from the environment.
type Config struct {
	APIKey         string
	WebhookSecret  string
	ProductMonthly string
	// ProductYearly unset means yearly is not offered.
	ProductYearly string
	// Secret signs the account claim in a checkout's metadata
	// (SENDSCORE_SECRET).
	Secret string
}

// Configured reports whether billing is on: an API key, a webhook secret,
// and the monthly product. Without them the app sells nothing.
func (c Config) Configured() bool {
	return c.APIKey != "" && c.WebhookSecret != "" && c.ProductMonthly != ""
}

// Missing names the settings a partly configured billing lacks.
func (c Config) Missing() []string {
	var out []string
	if c.APIKey == "" {
		out = append(out, "CREEM_API_KEY")
	}
	if c.WebhookSecret == "" {
		out = append(out, "CREEM_WEBHOOK_SECRET")
	}
	if c.ProductMonthly == "" {
		out = append(out, "CREEM_PRODUCT_PRO_MONTHLY")
	}
	return out
}

// Client talks to Creem.
type Client struct {
	cfg Config
	// Endpoint overrides the API base URL (tests).
	Endpoint string
	HTTP     *http.Client
}

// New returns a client for a configured billing.
func New(cfg Config) *Client {
	return &Client{cfg: cfg, HTTP: &http.Client{Timeout: 20 * time.Second}}
}

// Mode is "test" for a test key and "live" otherwise.
func (c *Client) Mode() string {
	if strings.HasPrefix(c.cfg.APIKey, TestKeyPrefix) {
		return "test"
	}
	return "live"
}

func (c *Client) base() string {
	if c.Endpoint != "" {
		return strings.TrimRight(c.Endpoint, "/")
	}
	if c.Mode() == "test" {
		return "https://test-api.creem.io"
	}
	return "https://api.creem.io"
}

// YearlyOffered reports whether Pro can be bought yearly.
func (c *Client) YearlyOffered() bool { return c.cfg.ProductYearly != "" }

// Product returns the product a period is bought as, or empty.
func (c *Client) Product(period string) string {
	switch period {
	case Monthly:
		return c.cfg.ProductMonthly
	case Yearly:
		return c.cfg.ProductYearly
	}
	return ""
}

// PeriodOf returns the period a product bills, or empty for a product this
// install does not sell.
func (c *Client) PeriodOf(productID string) string {
	switch {
	case productID == "":
		return ""
	case productID == c.cfg.ProductMonthly:
		return Monthly
	case productID == c.cfg.ProductYearly:
		return Yearly
	}
	return ""
}

// The account claim. metadata.userId alone cannot be trusted: Creem's
// payment links are public, and their metadata[key]=value query parameters
// come back in webhook events, so anyone who learns an account id could pay
// with their own card and bind the subscription to someone else's account.
// A buyer can set both fields and cannot forge the HMAC, so an id without a
// matching signature counts as no id at all.
const claimDomain = "creem-account:"

// SignClaim signs an account id for a checkout's metadata. It fails without
// a secret, before the customer reaches a card, since a checkout with no
// claim could never be matched to an account.
func (c *Client) SignClaim(userID string) (string, error) {
	if len(c.cfg.Secret) < MinSecretLen {
		return "", fmt.Errorf("%w: SENDSCORE_SECRET is not set", ErrNotSetUp)
	}
	m := hmac.New(sha256.New, []byte(c.cfg.Secret))
	m.Write([]byte(claimDomain + userID))
	return base64.RawURLEncoding.EncodeToString(m.Sum(nil)), nil
}

// ClaimHolds reports whether metadata really came from a checkout this app
// opened. It answers false, never an error, without a secret.
func (c *Client) ClaimHolds(userID, sig string) bool {
	if userID == "" || sig == "" {
		return false
	}
	want, err := c.SignClaim(userID)
	if err != nil {
		return false
	}
	return len(sig) == len(want) && subtle.ConstantTimeCompare([]byte(sig), []byte(want)) == 1
}

// VerifyWebhook reports whether a body really came from Creem: the hex
// HMAC-SHA256 of the raw body with the webhook secret, compared in constant
// time. No secret, no signature, or one of the wrong length is false.
func (c *Client) VerifyWebhook(raw []byte, signature string) bool {
	if c.cfg.WebhookSecret == "" || signature == "" {
		return false
	}
	m := hmac.New(sha256.New, []byte(c.cfg.WebhookSecret))
	m.Write(raw)
	want := hex.EncodeToString(m.Sum(nil))
	given := strings.ToLower(strings.TrimSpace(signature))
	return len(given) == len(want) && subtle.ConstantTimeCompare([]byte(given), []byte(want)) == 1
}

// post sends a JSON body to Creem and decodes the answer into out. A
// refusal is an error with the status, logged by the caller.
func (c *Client) post(ctx context.Context, path string, body, out any) (int, error) {
	if c.cfg.APIKey == "" {
		return 0, ErrNotSetUp
	}
	b, err := json.Marshal(body)
	if err != nil {
		return 0, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base()+path, bytes.NewReader(b))
	if err != nil {
		return 0, err
	}
	req.Header.Set("x-api-key", c.cfg.APIKey)
	req.Header.Set("Content-Type", "application/json")
	res, err := c.HTTP.Do(req)
	if err != nil {
		return 0, fmt.Errorf("could not reach Creem: %w", err)
	}
	defer res.Body.Close()
	data, err := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if err != nil {
		return res.StatusCode, fmt.Errorf("could not read Creem's answer: %w", err)
	}
	if res.StatusCode < 200 || res.StatusCode > 299 {
		return res.StatusCode, fmt.Errorf("creem refused %s (%d): %s", path, res.StatusCode, truncate(string(data), 400))
	}
	if out != nil {
		if err := json.Unmarshal(data, out); err != nil {
			return res.StatusCode, fmt.Errorf("creem answered %s with something that is not JSON: %w", path, err)
		}
	}
	return res.StatusCode, nil
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

// Checkout is what opening a checkout needs.
type Checkout struct {
	UserID string
	Email  string
	// CustomerID is the account's customer at Creem already, so a second
	// subscription is theirs rather than a new customer's.
	CustomerID string
	Period     string
	SuccessURL string
}

// CreateCheckout opens a checkout for one account and returns the address
// to send them to. The signed account claim rides in the metadata, which
// comes back on every webhook about the subscription.
func (c *Client) CreateCheckout(ctx context.Context, in Checkout) (string, error) {
	product := c.Product(in.Period)
	if product == "" {
		return "", fmt.Errorf("%w: no product for %q", ErrNotSetUp, in.Period)
	}
	sig, err := c.SignClaim(in.UserID)
	if err != nil {
		return "", err
	}
	// customer: {email}, not customer_email, which Creem refuses.
	customer := map[string]string{"email": in.Email}
	if in.CustomerID != "" {
		customer = map[string]string{"id": in.CustomerID}
	}
	var answer struct {
		CheckoutURL string `json:"checkout_url"`
		URL         string `json:"url"`
	}
	if _, err := c.post(ctx, "/v1/checkouts", map[string]any{
		"product_id":  product,
		"customer":    customer,
		"success_url": in.SuccessURL,
		"metadata":    map[string]string{"userId": in.UserID, "sig": sig},
	}, &answer); err != nil {
		return "", err
	}
	u := answer.CheckoutURL
	if u == "" {
		u = answer.URL
	}
	if !creemURL(u) {
		return "", fmt.Errorf("creem answered the checkout with no usable url (%q)", truncate(u, 200))
	}
	return u, nil
}

// PortalLink returns a short-lived link to Creem's page for a customer,
// where they change the card, read invoices, or cancel.
func (c *Client) PortalLink(ctx context.Context, customerID string) (string, error) {
	var answer struct {
		Link string `json:"customer_portal_link"`
	}
	if _, err := c.post(ctx, "/v1/customers/billing", map[string]string{"customer_id": customerID}, &answer); err != nil {
		return "", err
	}
	if !creemURL(answer.Link) {
		return "", fmt.Errorf("creem answered the portal with no usable url (%q)", truncate(answer.Link, 200))
	}
	return answer.Link, nil
}

// CancelSubscription stops a subscription now. already is set when Creem
// has no such subscription, which means there is nothing left to charge.
func (c *Client) CancelSubscription(ctx context.Context, subscriptionID string) (already bool, err error) {
	status, err := c.post(ctx, "/v1/subscriptions/"+url.PathEscape(subscriptionID)+"/cancel", map[string]any{}, nil)
	if status == http.StatusNotFound {
		return true, nil
	}
	return false, err
}

// CreemHosts are the hosts a checkout or portal link may send someone to,
// and what the pages' form-action allows when billing is on.
const CreemHosts = "https://creem.io https://*.creem.io"

// creemURL reports whether u is an https address at creem.io, so a strange
// answer never becomes a redirect somewhere else.
func creemURL(u string) bool {
	p, err := url.Parse(u)
	if err != nil || p.Scheme != "https" {
		return false
	}
	h := strings.ToLower(p.Hostname())
	return h == "creem.io" || strings.HasSuffix(h, ".creem.io")
}

// Event is a Creem webhook event.
type Event struct {
	ID        string          `json:"id"`
	EventType string          `json:"eventType"`
	CreatedAt json.RawMessage `json:"created_at"`
	Object    json.RawMessage `json:"object"`
}

// year2100 bounds a believable event time in milliseconds.
const year2100 = 4_102_444_800_000

// Time is when Creem says the event happened, in milliseconds, or 0. Creem
// has sent created_at in seconds and in milliseconds; a value below 1e12
// (2001 in milliseconds) is read as seconds. A value past 2100 is not
// believed, since one microsecond timestamp in the mark would make every
// later event look older and drop it.
func (e Event) Time() int64 {
	var f float64
	if err := json.Unmarshal(e.CreatedAt, &f); err != nil || math.IsNaN(f) || math.IsInf(f, 0) || f <= 0 {
		return 0
	}
	ms := f
	if f < 1e12 {
		ms = f * 1000
	}
	if ms > year2100 {
		return 0
	}
	return int64(math.Round(ms))
}

// Sub is what an event says about a subscription.
type Sub struct {
	SubscriptionID string
	CustomerID     string
	Email          string
	ProductID      string
	// UserID is set only when the metadata carries a signed claim.
	UserID    string
	Status    string
	PeriodEnd time.Time
}

type object struct {
	ID                   string          `json:"id"`
	Status               string          `json:"status"`
	Product              json.RawMessage `json:"product"`
	Customer             json.RawMessage `json:"customer"`
	CurrentPeriodEndDate string          `json:"current_period_end_date"`
	Metadata             map[string]any  `json:"metadata"`
	Subscription         json.RawMessage `json:"subscription"`
}

// idAndEmail reads a field that is either an id or an object with an id.
func idAndEmail(raw json.RawMessage) (id, email string) {
	if len(raw) == 0 {
		return "", ""
	}
	if json.Unmarshal(raw, &id) == nil {
		return id, ""
	}
	var o struct {
		ID    string `json:"id"`
		Email string `json:"email"`
	}
	if json.Unmarshal(raw, &o) == nil {
		return o.ID, o.Email
	}
	return "", ""
}

// ReadSubscription digs the subscription out of an event. A subscription
// event carries it as the object; a checkout event carries it as
// object.subscription, when the checkout made one, and the checkout's own
// id is never taken for a subscription's.
func (c *Client) ReadSubscription(e Event) Sub {
	var outer object
	_ = json.Unmarshal(e.Object, &outer)
	sub := outer
	checkout := strings.HasPrefix(e.EventType, "checkout.")
	if len(outer.Subscription) > 0 && string(outer.Subscription) != "null" {
		var nested object
		if json.Unmarshal(outer.Subscription, &nested) == nil {
			sub = nested
		} else if id, _ := idAndEmail(outer.Subscription); id != "" {
			sub = object{ID: id, Product: outer.Product, Customer: outer.Customer, Metadata: outer.Metadata}
		}
	} else if checkout {
		sub.ID, sub.Status, sub.CurrentPeriodEndDate = "", "", ""
	}
	if len(sub.Customer) == 0 {
		sub.Customer = outer.Customer
	}
	if len(sub.Product) == 0 {
		sub.Product = outer.Product
	}
	meta := sub.Metadata
	if meta == nil {
		meta = outer.Metadata
	}
	out := Sub{SubscriptionID: sub.ID, Status: sub.Status}
	out.ProductID, _ = idAndEmail(sub.Product)
	out.CustomerID, out.Email = idAndEmail(sub.Customer)
	uid, _ := meta["userId"].(string)
	sig, _ := meta["sig"].(string)
	if c.ClaimHolds(uid, sig) {
		out.UserID = uid
	}
	if t, err := time.Parse(time.RFC3339, sub.CurrentPeriodEndDate); err == nil {
		out.PeriodEnd = t.UTC()
	}
	return out
}
