package main

import (
	"Knights-Reach-Backend/database"
	_ "Knights-Reach-Backend/models"
	"Knights-Reach-Backend/routes"
	_ "github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
	_ "golang.org/x/crypto/bcrypt"
	_ "gorm.io/driver/sqlite"
	_ "gorm.io/gorm"
	"log"
	_ "net/http"
	_ "time"
)

func main() {
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}

	database.Connect()
	r := gin.Default()

	routes.AuthRoutes(r)

	r.Run(":3001") // server on port 3001
}
