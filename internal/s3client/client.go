package s3client

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

const emptyPayloadSHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

// ObjectInfo represents a single object returned by ListObjectsV2.
type ObjectInfo struct {
	Key          string
	Size         int64
	ETag         string
	LastModified time.Time
}

// ListResult holds one page of ListObjectsV2 results.
type ListResult struct {
	Objects               []ObjectInfo
	IsTruncated           bool
	NextContinuationToken string
}

// ReadOnlyClient is a minimal, zero-dependency, strictly read-only AWS SigV4 S3 client
// (ListObjectsV2 + GetObject only; no mutating/delete methods exist by design).
type ReadOnlyClient struct {
	endpoint   *url.URL
	region     string
	accessKey  string
	secretKey  string
	httpClient *http.Client
}

func NewReadOnly(endpoint, region, accessKey, secretKey string) (*ReadOnlyClient, error) {
	endpoint = strings.TrimSpace(endpoint)
	if endpoint == "" {
		return nil, fmt.Errorf("s3 endpoint is required")
	}
	u, err := url.Parse(strings.TrimRight(endpoint, "/"))
	if err != nil || u.Scheme == "" || u.Host == "" {
		return nil, fmt.Errorf("invalid s3 endpoint %q", endpoint)
	}
	if strings.TrimSpace(region) == "" {
		region = "us-east-1"
	}
	return &ReadOnlyClient{
		endpoint:  u,
		region:    region,
		accessKey: accessKey,
		secretKey: secretKey,
		httpClient: &http.Client{
			Transport: &http.Transport{
				MaxIdleConns:        64,
				MaxIdleConnsPerHost: 64,
				IdleConnTimeout:     90 * time.Second,
				ReadBufferSize:      1 << 20,
				WriteBufferSize:     256 << 10,
			},
		},
	}, nil
}

type listBucketResultXML struct {
	XMLName               xml.Name `xml:"ListBucketResult"`
	IsTruncated           bool     `xml:"IsTruncated"`
	NextContinuationToken string   `xml:"NextContinuationToken"`
	Contents              []struct {
		Key          string `xml:"Key"`
		LastModified string `xml:"LastModified"`
		ETag         string `xml:"ETag"`
		Size         int64  `xml:"Size"`
	} `xml:"Contents"`
}

func (c *ReadOnlyClient) ListObjectsV2(ctx context.Context, bucket, prefix, continuationToken string, maxKeys int) (*ListResult, error) {
	if maxKeys <= 0 || maxKeys > 1000 {
		maxKeys = 1000
	}
	q := url.Values{}
	q.Set("list-type", "2")
	q.Set("max-keys", strconv.Itoa(maxKeys))
	if prefix != "" {
		q.Set("prefix", prefix)
	}
	if continuationToken != "" {
		q.Set("continuation-token", continuationToken)
	}

	canonPath := "/" + awsURIEncode(bucket, false)
	rawURL := c.endpoint.Scheme + "://" + c.endpoint.Host + canonPath + "?" + buildCanonicalQuery(q)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	c.signRequest(req, canonPath, buildCanonicalQuery(q))

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("s3 ListObjectsV2 HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var parsed listBucketResultXML
	if err := xml.Unmarshal(body, &parsed); err != nil {
		return nil, fmt.Errorf("parse ListObjectsV2 xml: %w", err)
	}
	out := &ListResult{
		Objects:               make([]ObjectInfo, 0, len(parsed.Contents)),
		IsTruncated:           parsed.IsTruncated,
		NextContinuationToken: parsed.NextContinuationToken,
	}
	for _, it := range parsed.Contents {
		lm, _ := time.Parse(time.RFC3339Nano, it.LastModified)
		if lm.IsZero() {
			lm, _ = time.Parse(time.RFC3339, it.LastModified)
		}
		out.Objects = append(out.Objects, ObjectInfo{
			Key:          it.Key,
			Size:         it.Size,
			ETag:         strings.Trim(it.ETag, `"`),
			LastModified: lm,
		})
	}
	return out, nil
}

// GetObject opens a streaming read-only download of a single S3 object.
// Caller is responsible for closing resp.Body.
func (c *ReadOnlyClient) GetObject(ctx context.Context, bucket, key string) (*http.Response, error) {
	canonPath := "/" + awsURIEncode(bucket, false) + "/" + awsURIEncode(strings.TrimPrefix(key, "/"), true)
	rawURL := c.endpoint.Scheme + "://" + c.endpoint.Host + canonPath

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	c.signRequest(req, canonPath, "")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		_ = resp.Body.Close()
		return nil, fmt.Errorf("s3 GetObject %q HTTP %d: %s", key, resp.StatusCode, strings.TrimSpace(string(snippet)))
	}
	return resp, nil
}

func (c *ReadOnlyClient) signRequest(req *http.Request, canonicalURI, canonicalQuery string) {
	req.Host = c.endpoint.Host
	if c.accessKey == "" || c.secretKey == "" {
		return
	}
	now := time.Now().UTC()
	amzDate := now.Format("20060102T150405Z")
	dateStamp := now.Format("20060102")

	req.Header.Set("x-amz-date", amzDate)
	req.Header.Set("x-amz-content-sha256", emptyPayloadSHA256)

	canonicalHeaders := fmt.Sprintf("host:%s\nx-amz-content-sha256:%s\nx-amz-date:%s\n",
		c.endpoint.Host, emptyPayloadSHA256, amzDate)
	signedHeaders := "host;x-amz-content-sha256;x-amz-date"

	canonicalRequest := strings.Join([]string{
		req.Method,
		canonicalURI,
		canonicalQuery,
		canonicalHeaders,
		signedHeaders,
		emptyPayloadSHA256,
	}, "\n")

	crHash := sha256.Sum256([]byte(canonicalRequest))
	scope := fmt.Sprintf("%s/%s/s3/aws4_request", dateStamp, c.region)
	stringToSign := strings.Join([]string{
		"AWS4-HMAC-SHA256",
		amzDate,
		scope,
		hex.EncodeToString(crHash[:]),
	}, "\n")

	kDate := hmacSHA256([]byte("AWS4"+c.secretKey), dateStamp)
	kRegion := hmacSHA256(kDate, c.region)
	kService := hmacSHA256(kRegion, "s3")
	kSigning := hmacSHA256(kService, "aws4_request")
	signature := hex.EncodeToString(hmacSHA256(kSigning, stringToSign))

	authHeader := fmt.Sprintf("AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s",
		c.accessKey, scope, signedHeaders, signature)
	req.Header.Set("Authorization", authHeader)
}

func hmacSHA256(key []byte, data string) []byte {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(data))
	return mac.Sum(nil)
}

func buildCanonicalQuery(q url.Values) string {
	if len(q) == 0 {
		return ""
	}
	keys := make([]string, 0, len(q))
	for k := range q {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var parts []string
	for _, k := range keys {
		vals := append([]string(nil), q[k]...)
		sort.Strings(vals)
		ek := awsURIEncode(k, false)
		for _, v := range vals {
			parts = append(parts, ek+"="+awsURIEncode(v, false))
		}
	}
	return strings.Join(parts, "&")
}

// awsURIEncode encodes s according to AWS SigV4 rules (RFC 3986 unreserved characters).
func awsURIEncode(s string, keepSlash bool) string {
	var sb strings.Builder
	sb.Grow(len(s))
	const hexDigits = "0123456789ABCDEF"
	for i := 0; i < len(s); i++ {
		b := s[i]
		isUnreserved := (b >= 'A' && b <= 'Z') ||
			(b >= 'a' && b <= 'z') ||
			(b >= '0' && b <= '9') ||
			b == '-' || b == '_' || b == '.' || b == '~'
		if isUnreserved || (keepSlash && b == '/') {
			sb.WriteByte(b)
		} else {
			sb.WriteByte('%')
			sb.WriteByte(hexDigits[b>>4])
			sb.WriteByte(hexDigits[b&0x0f])
		}
	}
	return sb.String()
}
