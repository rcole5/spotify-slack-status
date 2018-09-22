package main

import (
	"fmt"
	"log"
	"net/http"
	"errors"
	"github.com/zmb3/spotify"
	"golang.org/x/oauth2"
	"context"
	"crypto/tls"
	"github.com/nlopes/slack"
	"strings"
	"time"
	"os"
	"encoding/json"
	"github.com/nu7hatch/gouuid"
	"os/signal"
	"runtime"
	"os/exec"
)

var (
	spotifyAuth    spotify.Authenticator
	slackAuth      Authenticator
	ch             = make(chan *spotify.Client)
	slackCh        = make(chan *oauth2.Token)
	state          string
	DefaultImage   string
	AppConfig      Config
)

type ConfigRecord struct {
	ClientId     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	RedirectUri  string `json:"redirect_uri"`
}

type Config struct {
	Port      string        `json:"port"`
	Emoji     string        `json:"emoji"`
	Frequency time.Duration `json:"frequency"`
	Spotify   ConfigRecord  `json:"spotify"`
	Slack     ConfigRecord  `json:"slack"`
}

type Session struct {
	SlackClient   *slack.Client
	SpotifyClient *spotify.Client
	DefaultMessage string
	DefaultEmoji string
}

func main() {
	// Load the config file
	file, err := os.Open("./config.json")
	if err != nil {
		log.Fatal(err)
	}

	decoder := json.NewDecoder(file)
	err = decoder.Decode(&AppConfig)
	if err != nil {
		log.Fatal(err)
	}

	// Start http server to handle callbacks
	http.HandleFunc("/spotifycallback", completeSpotifyAuth)
	http.HandleFunc("/slackcallback", completeSlackAuth)
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {})
	go http.ListenAndServe(":"+AppConfig.Port, nil)

	// Create the authenticators
	spotifyAuth = spotify.NewAuthenticator(AppConfig.Spotify.RedirectUri, spotify.ScopeUserReadPrivate, spotify.ScopeUserReadCurrentlyPlaying)
	slackAuth = NewSlackAuthenticator("users.profile:write", "users.profile:read", "users:read")

	// Generate oauth state
	state, err = GenerateStateToken()
	if err != nil {
		log.Fatal(err)
	}

	session, err := getClients()
	if err != nil {
		log.Fatal(err)
	}

	// Get the user id
	slackAuthTest, err := session.SlackClient.AuthTest()
	if err != nil {
		log.Fatal(err)
	}
	userId := slackAuthTest.UserID

	// Get default message and emoji
	user, err := session.SlackClient.GetUserProfile(userId, false)
	if err != nil {
		log.Fatal(err)
	}

	session.DefaultMessage = user.StatusText
	session.DefaultEmoji = user.StatusEmoji
	//DefaultImage = user.ImageOriginal

	// If we die then the status will be whatever we were last listening to
	// This captures the interrupt signal and resets the status
	killSig := make(chan os.Signal, 1)
	signal.Notify(killSig, os.Interrupt)
	signal.Notify(killSig, os.Kill)
	go func() {
		for range killSig {
			session.resetAndExit()
		}
	}()

	log.Println("Listening...")
	wasPlaying := false
	lastSong := spotify.CurrentlyPlaying{}

	// Create a ticker so we don't poll too often
	ticker := time.NewTicker(AppConfig.Frequency * time.Second)

	// Keep listening until we die
	for range ticker.C {
		// Get the current song
		current, err := session.SpotifyClient.PlayerCurrentlyPlaying()
		if err != nil {
			// When Spotify is in private mode it sends a response that the library can handle
			// This is a temporary work around
			if err.Error() == "EOF" {
				continue
			}
			session.resetAndFatal(err)
		}

		// Set status if currently player. Otherwise set it back to the original
		if current.Playing {
			// Check if song is the same
			if !wasPlaying || lastSong.Item.ID != current.Item.ID {
				// Format user list
				var artistList string
				for _, artist := range current.Item.Artists {
					artistList = artistList + ", " + artist.Name
				}

				// Trim the leading comma & trim the whitespace
				artistList = strings.TrimSpace(artistList[1:])

				// Format the message and set the status
				currentSong := "Listening to " + current.Item.Name + " by " + artistList
				if len(currentSong) > 99 {
					currentSong = currentSong[:97] + "..."
				}
				err = session.SlackClient.SetUserCustomStatus(currentSong, AppConfig.Emoji)
				//err = slackClient.SetUserPhoto(current.Item.Album.Images[0].URL, slack.UserSetPhotoParams{})
				if err != nil {
					// Just skip the update if we're rate limited
					if err.Error() != "rate_limited" {
						session.resetAndFatal(err)
					}
					continue
				}
				// We do this last to ensure the new status is set before we update these vars
				lastSong = *current
				wasPlaying = true
			}
		} else {
			// Music has stopped
			// No need to update if we 
			if wasPlaying {
				// Back to the defaults
				err = session.SlackClient.SetUserCustomStatus(session.DefaultMessage, session.DefaultEmoji)
				if err != nil {
					// Just skip the update if we're rate limited
					if err.Error() != "rate_limited" {
						session.resetAndFatal(err)
					}
				}
				wasPlaying = false
			}
		}
	}
}

// Login to Spotify & Slack then return the clients
func getClients() (session *Session, err error) {
	// Connect to Spotify
	spotifyClient, err := spotifyLogin()
	if err != nil {
		return
	}

	log.Println("Connected to Spotify!")

	// Connect to slack
	slackToken, err := slackLogin()
	if err != nil {
		return
	}

	log.Println("Connected to Slack!")

	// Create slack client
	slackClient := slack.New(slackToken.AccessToken)

	session = &Session{
		SpotifyClient: spotifyClient,
		SlackClient:   slackClient,
	}
	return
}

// Reset the message back to default & return a fatal.
func (s *Session) resetAndFatal(err error) {
	_ = s.SlackClient.SetUserCustomStatus(s.DefaultMessage, s.DefaultEmoji)
	log.Fatal(err.Error())
}

// Return the message back to default & exit.
func (s *Session) resetAndExit() {
	s.SlackClient.SetUserCustomStatus(s.DefaultMessage, s.DefaultEmoji)
	os.Exit(1)
}

// Start the Slack OAuth login flow.
func slackLogin() (token *oauth2.Token, err error) {
	// Prompt user to login
	url := slackAuth.AuthURL(state)
	openbrowser(url)
	fmt.Println("Please log in to Spotify by visiting the following page in your browser:", url)

	// Wait for the Slack auth to complete
	token = <-slackCh
	return
}

// Callback handler for the Slack OAuth login flow
func completeSlackAuth(w http.ResponseWriter, r *http.Request) {
	tok, err := slackAuth.Token(state, r)
	if err != nil {
		http.Error(w, "Couldn't get token", http.StatusForbidden)
	}
	if st := r.FormValue("state"); st != state {
		http.NotFound(w, r)
	}

	// Send the token
	slackCh <- tok
}

// Start the Spotify OAuth login flow.
func spotifyLogin() (client *spotify.Client, err error) {
	spotifyAuth.SetAuthInfo(AppConfig.Spotify.ClientId, AppConfig.Spotify.ClientSecret)

	url := spotifyAuth.AuthURL(state)
	openbrowser(url)
	fmt.Println("Please log in to Spotify by visiting the following page in your browser:", url)

	// Wait for the Spotify auth to complete
	client = <-ch
	return
}

// Callback handler for the Spotify OAuth login flow
func completeSpotifyAuth(w http.ResponseWriter, r *http.Request) {
	tok, err := spotifyAuth.Token(state, r)
	if err != nil {
		http.Error(w, "Couldn't get token", http.StatusForbidden)
	}
	if st := r.FormValue("state"); st != state {
		http.NotFound(w, r)
	}

	// use the token to get an authenticated client
	client := spotifyAuth.NewClient(tok)
	ch <- &client
}

// Generate a stake from a uuid.
func GenerateStateToken() (string, error) {
	id, err := uuid.NewV4()
	if err != nil {
		return "", err
	}
	return id.String(), nil
}

// Get the oauth token.
func (a Authenticator) Token(state string, r *http.Request) (*oauth2.Token, error) {
	values := r.URL.Query()
	if e := values.Get("error"); e != "" {
		return nil, errors.New("Slack: auth failed - " + e)
	}
	code := values.Get("code")
	if code == "" {
		return nil, errors.New("Slack: didn't get access code")
	}
	actualState := values.Get("state")
	if actualState != state {
		return nil, errors.New("Slack: redirect state parameter doesn't match")
	}
	return a.config.Exchange(a.context, code)
}

// Create an authenticator which is used to implement the OAuth2 authorization flow.
func NewSlackAuthenticator(scopes ...string) Authenticator {
	cfg := &oauth2.Config{
		ClientID:     AppConfig.Slack.ClientId,
		ClientSecret: AppConfig.Slack.ClientSecret,
		RedirectURL:  AppConfig.Slack.RedirectUri,
		Scopes:       scopes,
		Endpoint: oauth2.Endpoint{
			AuthURL:  "https://slack.com/oauth/authorize",
			TokenURL: "https://slack.com/api/oauth.access",
		},
	}

	tr := &http.Transport{
		TLSNextProto: map[string]func(authority string, c *tls.Conn) http.RoundTripper{},
	}
	ctx := context.WithValue(context.Background(), oauth2.HTTPClient, &http.Client{Transport: tr})
	return Authenticator{
		config:  cfg,
		context: ctx,
	}
}

func (a Authenticator) AuthURL(state string) string {
	return a.config.AuthCodeURL(state)
}

type Authenticator struct {
	config  *oauth2.Config
	context context.Context
}

func openbrowser(url string) (err error) {
	switch runtime.GOOS {
	case "linux":
		err = exec.Command("xdg-open", url).Start()
	case "windows":
		err = exec.Command("rundll32", "url.dll,FileProtocolHandler", url).Start()
	case "darwin":
		err = exec.Command("open", url).Start()
	default:
		err = fmt.Errorf("unsupported platform")
	}
	return
}
