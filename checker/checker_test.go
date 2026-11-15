package checker

import (
	"bytes"
	"image"
	"image/color"
	"image/png"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/ashendilantha/stalkie/loader"
	"github.com/ashendilantha/stalkie/matcher"
)

func TestEvaluateResponse(t *testing.T) {
	site := loader.Site{
		Name:          "TestGitHub",
		URL:           "https://example.com/{}",
		ErrorType:     "status_code",
		ErrorCode:     404,
		TitleContains: "GitHub",
		Weight:        10,
	}

	found, score, _ := evaluateResponse(site, "ashendilantha", 404, "Not Found", "https://example.com/ashendilantha")
	if found || score != 0 {
		t.Errorf("expected 404 to return false and 0 score, got found=%v score=%d", found, score)
	}

	bodyReal := "<html><head><title>ashendilantha - GitHub</title></head><body>ashendilantha profile content</body></html>"
	foundReal, scoreReal, _ := evaluateResponse(site, "ashendilantha", 200, bodyReal, "https://example.com/ashendilantha")
	if !foundReal || scoreReal < 80 {
		t.Errorf("expected valid profile to be found with high confidence, got found=%v score=%d", foundReal, scoreReal)
	}

	bodySoft404 := "<html><head><title>Page Not Found</title></head><body>This page does not exist</body></html>"
	foundSoft, scoreSoft, _ := evaluateResponse(site, "nonexistent", 200, bodySoft404, "https://example.com/nonexistent")
	if foundSoft || scoreSoft != 0 {
		t.Errorf("expected soft 404 to be rejected, got found=%v score=%d", foundSoft, scoreSoft)
	}
}

func TestCheckLiveMock(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/ashendilantha" {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("<html><head><title>ashendilantha Profile</title></head><body>ashendilantha info</body></html>"))
			return
		}
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte("Not Found"))
	}))
	defer server.Close()

	site := loader.Site{
		Name:      "MockService",
		URL:       server.URL + "/{}",
		ErrorType: "status_code",
		ErrorCode: 404,
		Weight:    8,
	}

	client := server.Client()
	client.Timeout = 2 * time.Second

	resValid := Check(client, site, "ashendilantha", 0, 0)
	if !resValid.Found {
		t.Errorf("expected found for valid user, got false")
	}

	resFake := Check(client, site, "nonexistent_user", 0, 0)
	if resFake.Found {
		t.Errorf("expected false for fake user, got true")
	}
}

func TestClusterResults(t *testing.T) {
	fpA := matcher.ImageFingerprint{
		Full: matcher.ScaleFingerprint{H: 0xAAAAAAAAAAAAAAAA, V: 0x5555555555555555, D: 0xF0F0F0F0F0F0F0F0, A: 0x0F0F0F0F0F0F0F0F},
		Mid:  matcher.ScaleFingerprint{H: 0xAAAAAAAAAAAAAAAA, V: 0x5555555555555555, D: 0xF0F0F0F0F0F0F0F0, A: 0x0F0F0F0F0F0F0F0F},
		Colors: [4]matcher.ColorQuad{
			{R: 120, G: 130, B: 140},
			{R: 120, G: 130, B: 140},
			{R: 120, G: 130, B: 140},
			{R: 120, G: 130, B: 140},
		},
	}

	results := []Result{
		{
			Username:          "alex",
			Site:              "GitHub",
			Found:             true,
			Confidence:        80,
			Evidence:          "HTTP 200, title match",
			AvatarFingerprint: fpA,
		},
		{
			Username:          "alex",
			Site:              "GitLab",
			Found:             true,
			Confidence:        85,
			Evidence:          "HTTP 200, title match",
			AvatarFingerprint: fpA,
		},
	}

	groups := ClusterResults(results, 75)
	if groups != 1 {
		t.Fatalf("expected 1 identity cluster, got %d", groups)
	}
	if results[0].ClusterID != "Identity Group A" || results[1].ClusterID != "Identity Group A" {
		t.Errorf("expected both results in Identity Group A, got %q and %q", results[0].ClusterID, results[1].ClusterID)
	}
	if results[0].ClusterSize != 2 {
		t.Errorf("expected ClusterSize 2, got %d", results[0].ClusterSize)
	}
}

func TestEndToEndAvatarClustering(t *testing.T) {
	imgA := image.NewRGBA(image.Rect(0, 0, 64, 64))
	for y := 0; y < 64; y++ {
		for x := 0; x < 64; x++ {
			if ((x*8)/64+(y*8)/64)%2 == 0 {
				imgA.Set(x, y, color.RGBA{R: 220, G: 50, B: 120, A: 255})
			} else {
				imgA.Set(x, y, color.RGBA{R: 20, G: 10, B: 40, A: 255})
			}
		}
	}

	var buf bytes.Buffer
	if err := png.Encode(&buf, imgA); err != nil {
		t.Fatalf("failed encoding test avatar: %v", err)
	}
	pngBytes := buf.Bytes()

	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/avatar.png" {
			w.Header().Set("Content-Type", "image/png")
			w.WriteHeader(http.StatusOK)
			w.Write(pngBytes)
			return
		}
		if r.URL.Path == "/alex_gh" || r.URL.Path == "/alex_gl" {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`<html><head><title>alex profile</title><meta property="og:image" content="` + server.URL + `/avatar.png"></head><body>alex developer</body></html>`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	sites := []loader.Site{
		{Name: "MockGitHub", URL: server.URL + "/{}_gh", ErrorType: "status_code", ErrorCode: 404, Weight: 10},
		{Name: "MockGitLab", URL: server.URL + "/{}_gl", ErrorType: "status_code", ErrorCode: 404, Weight: 10},
	}

	client := server.Client()
	client.Timeout = 2 * time.Second

	results := CheckAllWithOptions(client, sites, "alex", 2, 0, 0, nil, matcher.ImageFingerprint{}, 75, nil)
	clusters := ClusterResults(results, 75)
	if clusters != 1 {
		t.Fatalf("expected 1 unsupervised cluster from live check, got %d", clusters)
	}
	for _, r := range results {
		if r.ClusterID != "Identity Group A" || r.ClusterSize != 2 {
			t.Errorf("expected Identity Group A (size 2) on %s, got cluster=%q size=%d", r.Site, r.ClusterID, r.ClusterSize)
		}
	}
}




func TestOutcomeClassification(t *testing.T) {
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/ok":
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("<html><head><title>ok profile</title></head><body>ok info</body></html>"))
		case "/blocked":
			w.WriteHeader(http.StatusForbidden)
			w.Write([]byte("access denied"))
		case "/login":
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("<html><body>please log in</body></html>"))
		case "/elsewhere":
			http.Redirect(w, r, "/home", http.StatusFound)
		case "/home":
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("<html><head><title>home</title></head><body>welcome</body></html>"))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	// /profile/login redirects to the login page
	mux := http.NewServeMux()
	loginServer := httptest.NewServer(mux)
	defer loginServer.Close()
	mux.HandleFunc("/profile/", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/login", http.StatusFound)
	})
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("<html><body>sign in</body></html>"))
	})

	client := server.Client()
	client.Timeout = 2 * time.Second

	mkSite := func(name, url string) loader.Site {
		return loader.Site{Name: name, URL: url, ErrorType: "status_code", ErrorCode: 404}
	}

	resOK := Check(client, mkSite("OK", server.URL+"/ok"), "ok", 0, 0)
	if resOK.Outcome != OutcomeNormal {
		t.Errorf("expected outcome normal, got %q", resOK.Outcome)
	}

	resBlocked := Check(client, mkSite("Blocked", server.URL+"/blocked"), "blocked", 0, 0)
	if resBlocked.Outcome != OutcomeBlocked {
		t.Errorf("expected outcome blocked, got %q", resBlocked.Outcome)
	}

	resLogin := Check(client, mkSite("Login", loginServer.URL+"/profile/{}"), "someone", 0, 0)
	if resLogin.Outcome != OutcomeLoginRequired {
		t.Errorf("expected outcome login_required, got %q", resLogin.Outcome)
	}

	resRedir := Check(client, mkSite("Elsewhere", server.URL+"/elsewhere"), "elsewhere", 0, 0)
	if resRedir.Outcome != OutcomeRedirected {
		t.Errorf("expected outcome redirected, got %q", resRedir.Outcome)
	}

	badClient := server.Client()
	badClient.Timeout = 1 * time.Millisecond
	resDown := Check(badClient, mkSite("Down", "http://127.0.0.1:1/{}"), "down", 0, 0)
	if resDown.Outcome != OutcomeUnreachable {
		t.Errorf("expected outcome unreachable, got %q", resDown.Outcome)
	}
}

func TestClassifyRedirectMatchesLegacyBehavior(t *testing.T) {
	cases := []struct {
		target, final, body string
		wantClass           string
	}{
		{"https://x.com/u", "https://x.com/u", "hello", ""},
		{"https://x.com/u", "https://x.com/login", "", OutcomeLoginRequired},
		{"https://x.com/u", "https://x.com/u", "Log in to Instagram", OutcomeLoginRequired},
		{"https://x.com/u", "https://x.com/home", "welcome", ""},
	}
	for _, c := range cases {
		if got := classifyRedirect(c.target, c.final, c.body); got != c.wantClass {
			t.Errorf("classifyRedirect(%q,%q)=%q want %q", c.target, c.final, got, c.wantClass)
		}
		if legacy := isRedirectToLoginOrHome(c.target, c.final, c.body); legacy != (c.wantClass == OutcomeLoginRequired) {
			t.Errorf("legacy redirect check mismatch for %q -> %q", c.target, c.final)
		}
	}
}
