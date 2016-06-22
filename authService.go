package services
/**
Package Description: This package contains functions to authenticate and validate the client wants to retreive. 
Rejection of the resource will occure whenever the token is not valide. User will be logged out of the current session.
Developer: Uchenna Kevin Anyanwu
**/
import (
	"authService/util"
	"commonData"
	"commonData/dtos"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/astaxie/beego/logs"
	"io"
	"os"
)
/**
Description: Variables to be used by the package alone
**/
var (
	dataService commonData.DataService
	log         *logs.BeeLogger
)
/**
Description: Constants to be used by the package alone
**/
const (
	passSalt  = "johnisacoolguy"
	tokenSalt = "stupidTockenTest"
)
/**
Description: This is the authService struct
**/
type authService struct {
}
/**
Description: This is the authService interface with GetToken and Validate as functions to be implemented
Input: N/A
Outputs: N/A
**/
type AuthService interface {
	GetToken(email string, password string) (string, error)
	Validate(email string, token string) (bool, error)
}
/**
Description: This function returns an interface type of the auth service
Inputs: N/A
Outputs: Interface type of the authService
**/
func NewAuthService() AuthService {
	path := os.Getenv("PWD")
	fmt.Println("file path : ", path)
	dataService = commonData.NewDataServiceWithConfig(path + "/conf/app.conf")
	log = util.GetLogger()
	authService := authService{}
	return &authService
}
/**
Description: This function retrieves the token of the email and password sent by the user
Inputs: email string, password string
Output: result string, errObject error
**/
func (this *authService) GetToken(email string, password string) (string, error) {
	//instantiate local variables 
	log.Debug("dataService : ", dataService)
	var errorObject error
	c := make(map[string]interface{})
	
	//call supporting functions
	user, err := dataService.GetUserByEmail(email)
	contact := new(dtos.Contact)
    contact.FromUser(user, user.Password)
    
	//execute logic on those objects returned by the supporting functions
	var result string
	if err == nil {
		obj, _ := json.Marshal(contact)
		e := json.Unmarshal([]byte(obj), &c)
		log.Debug("user : ", user, " : e : ", e, " : map :", c)
		usrPass := getPasswordHash(password)
		dbPass := c["password"]
		log.Debug("usrPass :",usrPass, "dbPass :" , dbPass)
		delete(c, "password")
		if usrPass == dbPass {
			c["token"] = getTokenHash(email, usrPass)
			res, _ := json.Marshal(c)
			result = string(res)
		} else {
			errorObject = errors.New("auth faild for email : " + email)
		}
	} else {
		errorObject = err
	}
	//return the results
	return result, errorObject
}
/**
Description: This function returns the token hash of a username and user password
Inputs: userName string, usrPass string
Output: token string
**/
func getTokenHash(userName string, usrPass string) string {
	h256 := sha256.New()
	io.WriteString(h256, userName+usrPass+tokenSalt)
	token := hex.EncodeToString(h256.Sum(nil))
	return token
}
/**
Description: This funciton returnsa hash of the password
Input: password string
Output: usrPass string
**/
func getPasswordHash(password string) string {
	//instantiate local variables
	h := sha1.New()
	//call supporting functions
	io.WriteString(h, passSalt+password)
	usrPass := hex.EncodeToString(h.Sum(nil))
	//log some information
	log.Debug("usrPass: ", usrPass)
	//return result
	return usrPass
}
/**
Description: This function is used to validate the user that requests access to a back-end resource
Inputs: email string, token string
Output: result bool, errObject err
**/
func (this *authService) Validate(email string, token string) (bool, error) {

	//instantiate local variables 
	var errorObject error
	result := false
	c := make(map[string]interface{})
	
	//call supporting functions
	user, err := dataService.GetUserByEmail(email)
	contact := new(dtos.Contact)
    contact.FromUser(user, user.Password)

	//execute logic on those objects returned by the supporting functions
	if err == nil {
		obj, _ := json.Marshal(user)
		e := json.Unmarshal([]byte(obj), &c)
		if e == nil {
			password, okP := c["password"].(string)
			if okP == true {
				generatedToken := getTokenHash(email, password)
				if generatedToken == token {
					result = true
				}
			} else {
				errorObject = errors.New("password from db is not in valid format, email : " + email)
				log.Error("error from validate : ", errorObject)
			}
		} else {
			errorObject = e
		}
	} else {
		errorObject = err
	}
	
	//return the results
	return result, errorObject
}

