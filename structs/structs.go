package classes

import (
	"gopkg.in/mgo.v2"
)

type Person struct {
	Email    string `bson:"email" json:"email"`
	Password string `bson:"password" json:"password"`
	Hash     string `json: "hash, omitempty"`
	// Status   string `json: "status", bson:"status"`
} 

type Admin struct {
	Email    string `bson:"email" json:"email"`
	Password string `bson:"password" json:"password"`
	Hash     string `json: "hash, omitempty"`
}


type Session struct {
	S *mgo.Session
}

type Pizza struct {
	Name  string `bson:"name" json:"name"`
	Price int64  `bson:"price" json:"price,string,omitempty"`
}

type Order struct {
	Pizzas     []Pizza `bson:"pizzas" json:"pizzas"`
	OwnerEmail string  `bson:"ownerEmail" json:"ownerEmail"`
}

type CheckDataUser struct {
	CardNumber int64  `bson:"cardnumber" json:"cardnumber,string,omitempty"`
	Addres     string `bson:"addres" json:"addres"`
}

type Payment struct {
	Email        string          `bson:"email" json:"email"`
	Status       string          `bson:"status" json:"status"`
	OrderedPizza []Pizza         `bson:"orderedpizza" json:"orderedpizza, string, omitempty"`
	DataUser     []CheckDataUser `bson:"datauser" json:"datauser, string, omitempty"`
}

type Pin struct {
	PinAdm string `json: "pinadm"`
}

func (admin Admin) GetAdmin() ValueAdmin {
  	return admin
}

func (user Person) GetUser() ValueUser {
  	return user
}

type ValueUser interface {
  	GetUser() ValueUser
}

type ValueAdmin interface {
  	GetAdmin() ValueAdmin
}
