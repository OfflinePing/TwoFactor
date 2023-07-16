package database

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"github.com/pquerna/otp/totp"
	"io"
	_ "modernc.org/sqlite"
	"net/http"
	"os"
	"strings"
	"time"
)

var DB *sql.DB
var err error

type User struct {
	User string
	Pass string
	MFA  []Faktor
}

type Faktor struct {
	Name   string
	Secret string
}

var Faktors []User

func Encrypt(passphrase, text string) (string, error) {
	// Create a new AES-256 cipher with the SHA-256 of the passphrase
	hasher := sha256.New()
	hasher.Write([]byte(passphrase))
	block, err := aes.NewCipher(hasher.Sum(nil))
	if err != nil {
		return "", err
	}

	ciphertext := make([]byte, aes.BlockSize+len(text))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", err
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], []byte(text))

	return base64.URLEncoding.EncodeToString(ciphertext), nil
}
func Decrypt(passphrase, cipherText string) (string, error) {
	hasher := sha256.New()
	hasher.Write([]byte(passphrase))
	block, err := aes.NewCipher(hasher.Sum(nil))
	if err != nil {
		return "", err
	}

	decodedCipherText, err := base64.URLEncoding.DecodeString(cipherText)
	if err != nil {
		return "", err
	}

	if len(decodedCipherText) < aes.BlockSize {
		return "", errors.New("ciphertext block size is too short")
	}

	iv := decodedCipherText[:aes.BlockSize]
	decodedCipherText = decodedCipherText[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(decodedCipherText, decodedCipherText)

	return string(decodedCipherText), nil
}

func HashPassword(password string) string {
	h := sha256.New()
	h.Write([]byte(password))
	return string(h.Sum(nil))
}

func GetUserMFA(username string) []Faktor {
	for _, f := range Faktors {
		if f.User == username {
			return f.MFA
		}
	}
	return []Faktor{}
}

func GetFACode(pasword string, secret string) string {
	sec, err := Decrypt(pasword, secret)
	if err != nil {
		return ""
	}
	code, err := totp.GenerateCode(sec, time.Now())
	if err != nil {
		return ""
	}
	return code
}
func Connect() {
	DB, err = sql.Open("sqlite", "./database.db")
	if err != nil {
		panic(err)
	}
}

func Close() {
	DB.Close()
}

func CreateTables() {
	_, err := DB.Exec("CREATE TABLE IF NOT EXISTS faktor (user TEXT, password TEXT, mfa BLOB)")
	if err != nil {
		panic(err)
	}
}

func AddUser(username, password string) {
	faktors := []Faktor{}
	faktorsJson, err := json.Marshal(faktors)
	if err != nil {
		panic(err)
	}

	_, err = DB.Exec("INSERT INTO faktor VALUES (?, ?, ?)", username, HashPassword(password), faktorsJson)
	if err != nil {
		panic(err)
	}
	Faktors = append(Faktors, User{username, HashPassword(password), []Faktor{}})
}

func AddFaktor(name string, password string, secret string, username string) {
	faktors := GetUserMFA(username)
	encrypt, err := Encrypt(password, secret)
	if err != nil {
		panic(err)
	}
	faktors = append(faktors, Faktor{Name: name, Secret: encrypt})
	faktorsJson, err := json.Marshal(faktors)
	if err != nil {
		panic(err)
	}
	_, err = DB.Exec("UPDATE faktor SET mfa=? WHERE user=?", faktorsJson, username)
	if err != nil {
		panic(err)
	}
	Load()
}

func Load() {
	rows, err := DB.Query("SELECT * FROM faktor")
	if err != nil {
		panic(err)
	}
	defer rows.Close()

	Faktors = []User{}
	for rows.Next() {
		var username string
		var password string
		var mfaJSON []byte

		err = rows.Scan(&username, &password, &mfaJSON)
		if err != nil {
			panic(err)
		}

		var mfa []Faktor
		err = json.Unmarshal(mfaJSON, &mfa)
		if err != nil {
			panic(err)
		}

		Faktors = append(Faktors, User{username, HashPassword(password), mfa})
	}

	if err = rows.Err(); err != nil {
		panic(err)
	}
}

func DeleteFaktor(name string, username string) {
	faktor := RemoveFaktor(name, username)
	faktorJson, err := json.Marshal(faktor)
	_, err = DB.Exec("UPDATE faktor SET mfa=? WHERE user=?", faktorJson, username)
	if err != nil {
		panic(err)
	}
	for i, f := range Faktors {
		if f.User == username {
			Faktors[i].MFA = RemoveFaktor(name, username)
			break
		}
	}
}

func RemoveFaktor(name string, username string) []Faktor {
	var mfa []Faktor
	for _, f := range GetUserMFA(username) {
		if f.Name != name {
			mfa = append(mfa, f)
		}
	}
	return mfa
}

func Authenticate(username string, password string) bool {
	for _, user := range Faktors {
		if user.Pass == HashPassword(password) && user.User == username {
			return true
		}
	}
	return false
}

func Auth(w http.ResponseWriter, r *http.Request) bool {
	cookie, err := r.Cookie("session")
	if err != nil {
		return false
	}
	username := strings.Split(cookie.Value, " ")[0]
	password := strings.Split(cookie.Value, " ")[1]
	if Authenticate(username, password) {
		return true
	}
	return false
}

func CheckChars(text string) bool {
	chars := []string{";", " ", "'", "&", "*", "|", "<", ">", "$", "\\", "/", "@", "%", "."}
	for _, v := range chars {
		if strings.Contains(text, v) {
			return true
		}
	}
	return false
}

func GetFile(name string) string {
	file, err := os.Open(name)
	if err != nil {
		panic(err)
	}
	defer file.Close()

	b := make([]byte, 100000)
	n, err := file.Read(b)
	if err != nil {
		panic(err)
	}
	return string(b[:n])
}
