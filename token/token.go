package token

import (
	"os"
	"github.com/dgrijalva/jwt-go"
	"golang.org/x/crypto/bcrypt"
	"time"
	"github.com/gin-gonic/gin"
	"fmt"
	"sync"
)
var RWM sync.RWMutex

func CreateToken(userName string, userPassword string) (string, error) {
	var err error
	//Creating Access Token
	RWM.Lock()
	defer RWM.Unlock()
	os.Setenv("ACCESS_SECRET", "jdnfksdmfksd")
	atClaims := jwt.MapClaims{}
	atClaims["authorized"] = true
	atClaims["user_name"] = userName
	_, ok := atClaims["user_name"]
	if !ok {
		fmt.Println("CreateToken() => empty cookie")
		return "", nil
	}
	atClaims["user_password"] = userPassword
	_, ok = atClaims["user_password"]
	if !ok {
		fmt.Println("CreateToken() => empty cookie")
		return "", nil
	}
	atClaims["exp"] = time.Now().Add(time.Minute * 15)
	at := jwt.NewWithClaims(jwt.SigningMethodHS256, atClaims)
	token, err := at.SignedString([]byte(os.Getenv("ACCESS_SECRET")))
	if err != nil {
		return "", err
	}
	return token, nil
}



func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	return string(bytes), err
}

func CheckPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

func CheckTokenValidationUsers(c *gin.Context) {
	_, err := c.Cookie("token")
	if err != nil {
		fmt.Println("c.Cookie() ->", err.Error())
		c.HTML(200, "/user", gin.H{
			// "title": "authorisation", //IGNORE THIS
		})
		return
	}
	return
}

func CheckTokenValidationAdmins(c *gin.Context) {
	_, err := c.Cookie("token")
	if err != nil {
		fmt.Println("c.Cookie() ->", err.Error())
		c.HTML(200, "/admin", gin.H{
			"title": "authorisation", //IGNORE THIS
		})
		return
	}
	return
}