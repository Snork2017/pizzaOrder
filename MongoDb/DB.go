package checkDB

import (
	"github.com/gin-gonic/gin"
	"gopkg.in/mgo.v2"
	"gopkg.in/mgo.v2/bson"
	"fmt"
	"sync"
	"../structs"
	"../token"
)
/////////Заменить на CACHE, или брать данные с базы.
var RequestPin classes.Pin
var Order classes.Order
////////////////////////////////////
var ResultsOrder []classes.Order

var Database string = "developer"
var Session *mgo.Session
///////////////////////////////////////////////////
var RWM sync.RWMutex
func CheckPinAdm(c *gin.Context) {
	err := c.BindJSON(&RequestPin)
	if err != nil {
		fmt.Println("checkPinAdm =>", err.Error())
		return
	}
}

func CheckAdminPassword(login, password string) (classes.Admin, error) {
	var admin classes.Admin
	collection := Session.DB("developer").C("admins")
	err := collection.Find(bson.M{"email": login}).One(&admin)
	if err != nil {
		fmt.Println("CheckUserPassword() ->", err.Error())
		return classes.Admin{}, err
	}
	if token.CheckPasswordHash(password, admin.Hash) == true {
		return admin, nil
	} else {
		return admin, fmt.Errorf("Неверный логин, или пароль!")
	}
}

func CheckUserPassword(login, password string) (classes.Person, error) {
	var person classes.Person
	collection := Session.DB("developer").C("people")
	err := collection.Find(bson.M{"email": login}).One(&person)
	if err != nil {
		fmt.Println("CheckUserPassword() ->", err.Error())
		return classes.Person{}, err
	}
	if token.CheckPasswordHash(password, person.Hash) == true {
		return person, nil
	} else {
		return person, fmt.Errorf("Неверный логин, или пароль!")
	}
}

func ReadPizza(c *mgo.Collection, emailCookie string) {
	Order = classes.Order{}
	filterPizza := make(map[string]interface{})
	RWM.Lock()
	filterPizza["ownerEmail"] = emailCookie
	RWM.Unlock()
	_, ok := filterPizza["ownerEmail"]
	if !ok {
		fmt.Println("ReadPizza() => empty cookie")
		return
	}
	query := c.Find(filterPizza)
	err := query.One(&Order)
	if err != nil {
		fmt.Println("query.All() ->", err)
		return
	}
	for _, value := range Order.Pizzas {
		fmt.Println(value)
	}
	fmt.Printf("\n")
}

func ReadOrder(c *mgo.Collection) {
	query := c.Find(bson.M{})
	err := query.All(&ResultsOrder)
	if err != nil {
		fmt.Println("query.All() ->", err)
		return
	}
	for _, value := range ResultsOrder {
		fmt.Println("readOrder" , value)
	}

	fmt.Printf("\n")
}




func BootstrapPizza(s *mgo.Session) *mgo.Collection {
	c := s.DB(Database).C("pizza")
	index := mgo.Index{
		Key:        []string{"name"},
		Unique:     true,
		Background: true,
	}
	err := c.EnsureIndex(index)
	if err != nil {
		fmt.Println("EnsureIndex() ->", err.Error())
		return nil
	}
	return c
}

func BootstrapOrder(s *mgo.Session) *mgo.Collection {
	c := s.DB(Database).C("order")
	index := mgo.Index{
		Key:        []string{"pizzas"},
		Unique:     true,
		Background: true,
	}
	err := c.EnsureIndex(index)
	if err != nil {
		fmt.Println("EnsureIndex() ->", err.Error())
		return nil
	}
	return c
}

func BootstrapPeople(s *mgo.Session) *mgo.Collection {
	c := s.DB(Database).C("people")
	index := mgo.Index{
		Key:        []string{"email"},
		Unique:     true,
		Background: true,
	}
	err := c.EnsureIndex(index)
	if err != nil {
		fmt.Println("EnsureIndex() ->", err.Error())
		return nil
	}

	return c
}

func BootstrapAdmins(s *mgo.Session) *mgo.Collection {
	c := s.DB(Database).C("admins")
	index := mgo.Index{
		Key:        []string{"email"},
		Unique:     true,
		Background: true,
	}
	err := c.EnsureIndex(index)
	if err != nil {
		fmt.Println("EnsureIndex() ->", err.Error())
		return nil
	}
	return c
}


func CheckUserInDb(login, password string) (classes.Person, error) {
	var person classes.Person
	hash, err := token.HashPassword(password)
	if err != nil {
		fmt.Println("HashPassword() ->", err.Error())
		return person, err
	}
	collection := Session.DB("developer").C("people")
	err = collection.Find(bson.M{"email": login}).One(&person)
	if err != nil {
		person := classes.Person{
			Email:    login,
			Password: password,
			Hash:     hash,
		}
		return person, nil
	}
	return classes.Person{}, fmt.Errorf("Такой пользователь уже существует!")
}

func CheckAdminInDb(login, password string) (classes.Admin, error) {
	var admin classes.Admin
	hash, err := token.HashPassword(password)
	if err != nil {
		fmt.Println("HashPassword() ->", err.Error())
		return admin, err
	}
	collection := Session.DB("developer").C("admins")
	err = collection.Find(bson.M{"email": login}).One(&admin)
	if err != nil {
		admin := classes.Admin{
			Email:    login,
			Password: password,
			Hash:     hash,
		}
		return admin, nil
	}
	return classes.Admin{}, fmt.Errorf("Такой администратор уже существует!")
}