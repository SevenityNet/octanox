package octanox

import (
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

type BearerAuthenticator struct {
	provider UserProvider
	secret   []byte
	exp      int64
}

// SetExp sets the expiration time for the token.
func (a *BearerAuthenticator) SetExp(exp int64) {
	a.exp = exp
}

func (a *BearerAuthenticator) Method() AuthenticationMethod {
	return AuthenticationMethodBearer
}

func (a *BearerAuthenticator) Authenticate(c *gin.Context) (User, error) {
	token := c.GetHeader("Authorization")
	if token == "" || len(token) <= 7 || !strings.HasPrefix(token, "Bearer ") {
		return nil, nil
	}

	userID := a.extractToken(token[7:])
	if userID == nil {
		return nil, nil
	}

	user, err := a.provider.ProvideByID(*userID)
	if err != nil {
		return nil, err
	}

	return user, nil
}

func (a *BearerAuthenticator) login(c *gin.Context) {
	username := c.PostForm("username")
	password := c.PostForm("password")

	if username == "" || password == "" {
		c.JSON(400, gin.H{"error": "missing username or password"})
		return
	}

	user, err := a.provider.ProvideByUserPass(username, password)
	if err != nil {
		panic(err)
	}

	if user == nil {
		c.JSON(401, gin.H{"error": "invalid username or password"})
		return
	}

	token, err := a.createToken(user)
	if err != nil {
		panic("octanox: failed to create token")
	}

	c.JSON(200, gin.H{
		"token": token,
		"exp":   a.exp,
	})
}

func (a *BearerAuthenticator) registerRoutes(r *gin.RouterGroup) {
	r.POST("/login", a.login)
}

func (a *BearerAuthenticator) createToken(user User) (string, error) {
	currTime := time.Now().Unix()
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"iss": "Octanox Auth",
		"aud": "octanox",
		"sub": user.ID(),
		"exp": time.Now().Add(time.Second * time.Duration(a.exp)).Unix(),
		"iat": currTime,
		"nbf": currTime,
		"jti": uuid.New().String(),
	})

	return token.SignedString(a.secret)
}

func (a *BearerAuthenticator) extractToken(tokenString string) *uuid.UUID {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, jwt.ErrSignatureInvalid
		}

		return a.secret, nil
	})
	if err != nil {
		return nil
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		subClaim, ok := claims["sub"]
		if !ok {
			return nil
		}

		subject, err := uuid.Parse(subClaim.(string))
		if err != nil {
			return nil
		}

		return &subject
	}

	return nil
}
