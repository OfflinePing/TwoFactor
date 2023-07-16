package main

import (
	"TwoFaktor/database"
	"encoding/json"
	"fmt"
	"golang.org/x/net/websocket"
	"net/http"
	"os"
	"strings"
	"time"
)

type Server struct {
	conns map[*websocket.Conn]bool
}

func NewServer() *Server {
	return &Server{
		conns: make(map[*websocket.Conn]bool),
	}
}

type Config struct {
	Port string
}

var CFG Config

func (s *Server) handleWSOrder(ws *websocket.Conn) {
	fmt.Println("New Orderbook Client Connection: ", ws.RemoteAddr())

	user, err := ws.Request().Cookie("session")
	if err != nil {
		fmt.Println("No cookie found")
		return
	}

	username := strings.Split(user.Value, " ")[0]
	password := strings.Split(user.Value, " ")[1]

	go func() {
		for {
			buf := make([]byte, 1024)
			n, err := ws.Read(buf)
			if err != nil {
				fmt.Println("Error reading message: ", err.Error())
				return
			}
			msg := string(buf[:n])
			if strings.Contains(msg, "ADD> ") {
				msg = strings.Replace(msg, "ADD> ", "", 1)
				if database.GetFA(strings.Split(msg, ":")[1]) == "" {
					continue
				} else {
					database.AddFaktor(strings.Split(msg, ":")[0], password, strings.Split(msg, ":")[1], username)
				}
			}
			if strings.Contains(msg, "DELETE> ") {
				msg = strings.Replace(msg, "DELETE> ", "", 1)
				database.DeleteFaktor(strings.Split(msg, ":")[0], username)
			}
		}
	}()

	for {
		var msg string
		for _, mfa := range database.GetUserMFA(username) {
			code := database.GetFACode(password, mfa.Secret)
			if code != "" {
				msg += mfa.Name + ":" + code + ","
			}
		}
		if len(msg) > 0 {
			msg = strings.TrimSuffix(msg, ",")
			err := websocket.Message.Send(ws, msg)
			if err != nil {
				fmt.Println("Error sending message: ", err.Error())

				return
			}
		}
		time.Sleep(500 * time.Millisecond)
	}
}

func SetSession(username string, key string, w http.ResponseWriter) {
	expiration := time.Now().Add(6 * time.Hour)
	cookie := http.Cookie{Name: "session", Value: username + " " + key, Expires: expiration}
	http.SetCookie(w, &cookie)
}

func RegisterPage(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		username := r.FormValue("username")
		password := r.FormValue("password")
		if len(username) == 0 || len(password) == 0 {
			fmt.Println("Username or password is empty")
			return
		}
		if database.CheckChars(username) || database.CheckChars(password) {
			fmt.Println("Username or password contains invalid characters")
			return
		}
		database.AddUser(username, password)
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	w.WriteHeader(http.StatusAccepted)
	w.Write([]byte(database.GetFile("web/register.html")))
}

func LoginPage(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		username := r.FormValue("username")
		password := r.FormValue("password")
		if len(username) == 0 || len(password) == 0 {
			fmt.Println("Username or password is empty")
			return
		}
		if database.Authenticate(username, password) {
			SetSession(username, password, w)
			http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
			return
		}
	}
	w.WriteHeader(http.StatusAccepted)
	w.Write([]byte(database.GetFile("web/index.html")))
}

func DashboardPage(w http.ResponseWriter, r *http.Request) {
	if !database.Auth(w, r) {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	w.WriteHeader(http.StatusAccepted)

	ses, err := r.Cookie("session")
	if err != nil {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	name := strings.Split(ses.Value, " ")[0]
	dash := strings.NewReplacer("{{name}}", name, "{{port}}", CFG.Port).Replace(database.GetFile("web/dashboard.html"))

	w.Write([]byte(dash))
}

func main() {
	database.Connect()
	fmt.Println("Connected to database")
	database.CreateTables()
	fmt.Println("Created tables")
	database.Load()
	fmt.Println("Loaded data")

	file, err := os.Open("config.json")
	if err != nil {
		fmt.Println("Error loading config file")
		return
	}

	decoder := json.NewDecoder(file)
	err = decoder.Decode(&CFG)
	if err != nil {
		fmt.Println("Error decoding config file")
		return
	}

	defer database.Close()
	server := NewServer()
	http.Handle("/ws", websocket.Handler(server.handleWSOrder))
	http.HandleFunc("/", LoginPage)
	http.HandleFunc("/dashboard", DashboardPage)
	http.HandleFunc("/register", RegisterPage)
	http.ListenAndServe(":"+CFG.Port, nil)
}
