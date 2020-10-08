package main

import (
	"./MongoDb"
	"./structs"
	"./token"
	"fmt"
	"github.com/gin-gonic/gin"
	"gopkg.in/mgo.v2"
	"gopkg.in/mgo.v2/bson"
	"net/http"
	"sync"
)

/////////Заменить на CACHE, или брать данные с базы.
var paymentArray []classes.Payment
var resultsPizzas []classes.Pizza
var requestPizza classes.Pizza
var mySigningKey = []byte("MySeretToken")
var resultsPizzaAdm []classes.Pizza
var checkPizza classes.Pizza
var checkPizzaArray []classes.Pizza
var checkDataUser classes.CheckDataUser
var checkDataUserArray []classes.CheckDataUser
var status string
var sum int64
var database string = "developer"
var RWM sync.RWMutex

/////////////////////////////////////////////////////////////////////
type Collection struct {
	C *mgo.Collection
}

var cacheAdmin *CacheAdmin
var cacheUser *CacheUser

func readAdmins(c *mgo.Collection) {
	var resultsAdmins []classes.Admin
	err := c.Find(bson.M{}).All(&resultsAdmins)
	if err != nil {
		fmt.Println("query.All() ->", err)
		return
	}
	for _, value := range resultsAdmins {
		cacheAdmin.SetAdmin(value.Email, value)
	}
	fmt.Printf("\n")
	fmt.Println(cacheAdmin.Items)
}

func readPeople(c *mgo.Collection) {
	var resultsPerson []classes.Person
	err := c.Find(bson.M{}).All(&resultsPerson)
	if err != nil {
		fmt.Println("query.All() ->", err)
		return
	}
	for _, value := range resultsPerson {
		cacheUser.SetUser(value.Email, value)
	}
	fmt.Println("readPeople", cacheUser.Items)
	fmt.Printf("\n")
}

type CacheAdmin struct {
	Items map[string]classes.ValueAdmin
	sync.RWMutex
}

type CacheUser struct {
	Items map[string]classes.ValueUser `json: "items"`
	sync.RWMutex
}

func NewUser() *CacheUser {
	Items := make(map[string]classes.ValueUser)
	cache := CacheUser{
		Items: Items,
	}
	return &cache
}

func NewAdmin() *CacheAdmin {
	Items := make(map[string]classes.ValueAdmin)
	cache := CacheAdmin{
		Items: Items,
	}
	return &cache
}

func (cu *CacheUser) SetUser(key string, value classes.ValueUser) {
	cu.Lock()
	cu.Items[key] = value
	cu.Unlock()
}

func (ca *CacheAdmin) SetAdmin(key string, value classes.ValueAdmin) {
	ca.Lock()
	ca.Items[key] = value
	ca.Unlock()
}

// func (cu *CacheUser) DeleteUser(key string) error {
//   	cu.Lock()
//   	defer cu.Unlock()
//   	if _, found := cu.Items[key]; !found {
//     	return errors.New("Key NOT found")
//   	}
//   	delete(cu.Items, key)
//   	return nil
// }

func (people *Collection) signUpUsers(c *gin.Context) {
	// userStatus := "Hawaewafggewkfjke"
	c.Request.ParseForm()
	p := people.C
	eMail := c.PostForm("EMailReg")
	password := c.PostForm("passwordReg")
	_, err := checkDB.CheckUserInDb(eMail, password)
	if err != nil {
		c.HTML(http.StatusOK, "UserExists.html", gin.H{
			"err": err,
		})
		return
	}
	hash, _ := token.HashPassword(password)
	token.CheckPasswordHash(password, hash)
	err = p.Insert(
		&classes.Person{Email: eMail, Password: password, Hash: hash},
	)
	if err != nil {
		fmt.Println(err)
		return
	}
	c.HTML(http.StatusOK, "UserReged.html", gin.H{
		"succesfully": "Пользователь зарегистрирован успешно!",
		"email":       eMail,
		"password":    password,
	})
	readPeople(p)
}

///Добавить поиск пиццы по названию!
///Добавить отмена заказа!
///Добавить удаление заказа при оплате!
///Добавить удаление(бан) пользователей в админке!
func payedOrder(c *gin.Context) {
	c.Request.ParseForm()
	eMail := c.PostForm("email")
	fmt.Println(eMail)
	payment := classes.Payment{
		Email:        " ",
		Status:       " ",
		OrderedPizza: nil,
		DataUser:     nil,
	}
	paymentArray = append(paymentArray, payment)
	c.String(http.StatusOK, "Ваш заказ успешно оплачен, ожидайте товар в течении 15-20 минут, мы вам перезвоним")
}

//////////////////////////////////////
func savePizzaAdmin(c *gin.Context) {
	var jsonPizza classes.Pizza
	err := c.BindJSON(&jsonPizza)
	if err != nil {
		fmt.Println("savePizzaAdmin() =>", err.Error())
		return
	}
	resultsPizzaAdm = append(resultsPizzaAdm, jsonPizza)
}

func paymentPizza(c *gin.Context) {
	err := c.BindJSON(&checkDataUser)
	if err != nil {
		fmt.Println("deletePizzaFromTrash() ->", err.Error())
		return
	}
	checkDataUserArray = append(checkDataUserArray, checkDataUser)

	email, _ := c.Cookie("email")
	payment := classes.Payment{
		Email:        email,
		Status:       "Не оплачен",
		OrderedPizza: checkPizzaArray,
		DataUser:     checkDataUserArray,
	}
	paymentArray = append(paymentArray, payment)
	fmt.Println(payment)
	fmt.Println(paymentArray)
	sum += checkPizza.Price
	fmt.Println("Общая сумма", sum)
}

func checkOrderedPizza(c *gin.Context) {
	err := c.BindJSON(&checkPizza)
	if err != nil {
		fmt.Println("checkOrderedPizza() ->", err.Error())
		return
	}
	checkPizzaArray = append(checkPizzaArray, checkPizza)
	fmt.Println("checkPizza =>", checkPizza)
	fmt.Println("checkPizzaARRAY =>", checkPizzaArray)
}

func unCheckOrderedPizza(c *gin.Context) {
	err := c.BindJSON(&checkPizza)
	if err != nil {
		fmt.Println("checkOrderedPizza() ->", err.Error())
		return
	}
	for k := range checkPizzaArray {
		if checkPizzaArray[k].Name == checkPizza.Name {
			checkPizzaArray[k] = checkPizzaArray[len(checkPizzaArray)-1]
			checkPizzaArray = checkPizzaArray[:len(checkPizzaArray)-1]
			break
		}
	}
	fmt.Println("UNCHECKEDPIZZA =>", checkPizzaArray)
}

func (pizza *Collection) deletePizzaFromTrash(c *gin.Context) {
	var p = pizza.C
	emailCookie, err := c.Cookie("email")
	if err != nil {
		fmt.Println("deletePizzaFromTrash() => emailCookie() ->", err.Error())
		return
	}
	var deletePizza classes.Pizza
	err = c.BindJSON(&deletePizza)
	if err != nil {
		fmt.Println("deletePizzaFromTrash() ->", err.Error())
		return
	}
	for k := range checkDB.Order.Pizzas {
		if checkDB.Order.Pizzas[k].Name == deletePizza.Name {
			checkDB.Order.Pizzas[k] = checkDB.Order.Pizzas[len(checkDB.Order.Pizzas)-1]
			checkDB.Order.Pizzas = checkDB.Order.Pizzas[:len(checkDB.Order.Pizzas)-1]
			break
		}
	}
	filterPizza := make(map[string]interface{})
	// RWM.Lock()
	filterPizza["ownerEmail"] = emailCookie
	// RWM.Unlock()
	_, ok := filterPizza["ownerEmail"]
	if !ok {
		fmt.Println("deletePizzaFromTrash() => empty cookie")
		return
	}
	change := bson.M{
		"$set": bson.M{
			"pizzas": checkDB.Order.Pizzas,
		},
	}

	err = p.Update(filterPizza, change)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(deletePizza)
	resultsPizzaAdm = append(resultsPizzaAdm, deletePizza)
}

func (pizza *Collection) pizzaOrder(c *gin.Context) {
	p := pizza.C
	emailCookie, err := c.Cookie("email")
	if err != nil {
		fmt.Println("pizzaOrder() => empty cookie")
		return
	}
	fmt.Println(emailCookie)
	err = c.BindJSON(&requestPizza)
	if err != nil {
		fmt.Println("orderPizza() 110 ->", err.Error())
		return
	}
	filterPizza := make(map[string]interface{})
	filterPizza["ownerEmail"] = emailCookie
	// RWM.Lock()
	_, ok := filterPizza["ownerEmail"]
	// RWM.Unlock()
	if !ok {
		fmt.Println("pizzaOrder() => empty cookie")
		return
	}
	err = p.Find(filterPizza).One(&checkDB.Order)
	if err != nil {
		fmt.Println("c.FIND().ONE() ->", err.Error())
		orderPizza := classes.Pizza{
			Name:  requestPizza.Name,
			Price: requestPizza.Price,
		}
		pizzas := []classes.Pizza{}
		checkDB.Order.OwnerEmail = emailCookie
		pizzas = append(pizzas, orderPizza)
		checkDB.Order.Pizzas = pizzas
		err = p.Insert(
			&checkDB.Order,
		)
		if err != nil {
			fmt.Println("c.Insert{order} ->", err.Error())
			return
		}
	} else {
		orderPizza := classes.Pizza{
			Name:  requestPizza.Name,
			Price: requestPizza.Price,
		}
		ordPizzas := checkDB.Order.Pizzas
		ordPizzas = append(ordPizzas, orderPizza)
		change := bson.M{
			"$set": bson.M{
				"pizzas": ordPizzas,
			},
		}

		err := p.Update(filterPizza, change)
		if err != nil {
			fmt.Println(err.Error())
			return
		}
		for k := range resultsPizzaAdm {
			if resultsPizzaAdm[k].Name == requestPizza.Name {
				resultsPizzaAdm[k] = resultsPizzaAdm[len(resultsPizzaAdm)-1]
				resultsPizzaAdm = resultsPizzaAdm[:len(resultsPizzaAdm)-1]
				fmt.Println(resultsPizzaAdm[k].Name)
				break
			}
		}
	}
	checkDB.ReadPizza(p, emailCookie)
	resultsPizzas = append(resultsPizzas, requestPizza)
}

func loginAdmin(c *gin.Context) {
	c.Request.ParseForm()
	eMail := c.PostForm("EMailLog")
	if eMail == " " {
		fmt.Println("The field => Email is empty")
		return
	}
	password := c.PostForm("passwordLog")
	if password == " " {
		fmt.Println("The field => password is empty")
		return
	}
	token, err := token.CreateToken(eMail, password)
	if err != nil {
		token = "nil"
		fmt.Println("CreateToken() ->", err.Error())
		return
	}
	_, err = checkDB.CheckAdminPassword(eMail, password)
	if err != nil {
		token = "nil"
		c.HTML(http.StatusOK, "wrongLoginADM.html", gin.H{
			"err": err,
		})
		return
	} else {
		c.SetCookie("token", token, 3600, "/", "localhost", false, false)
		c.SetCookie("email", eMail, 3600, "/", "localhost", false, false)
		c.SetCookie("status", "admin", 3600, "/", "localhost", false, false)
		c.HTML(http.StatusOK, "accountAdmin.html", gin.H{
			"email": eMail,
		})
	}
}

func (people *Collection) loginUser(c *gin.Context) {
	c.Request.ParseForm()
	p := people.C
	eMail := c.PostForm("EMailLog")
	if eMail == " " {
		fmt.Println("The field => Email is empty")
		return
	}
	password := c.PostForm("passwordLog")
	if password == " " {
		fmt.Println("The field => password is empty")
		return
	}
	token, err := token.CreateToken(eMail, password)
	if err != nil {
		token = "nil"
		return
	}
	_, err = checkDB.CheckUserPassword(eMail, password)
	if err != nil {
		token = "nil"
		c.HTML(http.StatusOK, "wrongLoginUSER.html", gin.H{
			"err": err,
		})
		return
	}
	c.SetCookie("token", token, 3600, "/", "localhost", false, false)
	c.SetCookie("email", eMail, 3600, "/", "localhost", false, false)
	c.SetCookie("status", "user", 3600, "/", "localhost", false, false)
	c.HTML(http.StatusOK, "accountUser.html", gin.H{
		"email": eMail,
	})

	checkDB.ReadPizza(p, eMail)
}

func (people *Collection) signUpAdmins(c *gin.Context) {
	c.Request.ParseForm()
	// var person Person
	p := people.C
	eMail := c.PostForm("EMailReg")
	password := c.PostForm("passwordReg")
	_, err := checkDB.CheckAdminInDb(eMail, password)
	if err != nil {
		c.HTML(http.StatusOK, "AdminExists.html", gin.H{
			"err": err,
		})
		return
	}
	hash, _ := token.HashPassword(password)
	token.CheckPasswordHash(password, hash)
	err = p.Insert(
		&classes.Admin{Email: eMail, Password: password, Hash: hash},
	)
	if err != nil {
		fmt.Println(err)
		return
	}
	c.HTML(http.StatusOK, "AdminReged.html", gin.H{
		"succesfully": "Администратор зарегистрирован успешно!",
		"email":       eMail,
		"password":    password,
	})
	readAdmins(p)
}

func logoutUser(c *gin.Context) {
	// Clear the cookie
	c.SetCookie("token", "", -1, "", "", false, true)
	c.SetCookie("email", "", -1, "", "", false, true)
	c.SetCookie("status", "", -1, "", "", false, true)
	c.Set("isLoggedIn", false)
	// Redirect to the home page
	c.Redirect(http.StatusFound, "/user")
}

func logoutAdmin(c *gin.Context) {
	// Clear the cookie
	c.SetCookie("token", "", -1, "", "", false, true)
	c.SetCookie("email", "", -1, "", "", false, true)
	c.SetCookie("status", "", -1, "", "", false, true)
	c.Set("isLoggedIn", false)
	// Redirect to the home page
	c.Redirect(http.StatusFound, "/admin")
}

func (people *Collection) banUser(c *gin.Context) {
	var requestUser string
	p := people.C
	err := c.Bind(&requestUser)
	if err != nil {
		fmt.Println("banUser() ->", err.Error())
		return
	}
	RWM.Lock()
	for k := range cacheUser.Items {
		if k == requestUser {
			if _, found := cacheUser.Items[k]; !found {
				fmt.Println("not found")
				RWM.Unlock()
				return
			} else {
				delete(cacheUser.Items, k)
			}
		}
	}
	RWM.Unlock()
	filter := make(bson.M)
	filter["email"] = requestUser
	err = p.Remove(filter)

	if err != nil {
		fmt.Println(err)
		return
	}
	readPeople(p)
}

func main() {
	cacheAdmin = NewAdmin()
	cacheUser = NewUser()
	var err error
	checkDB.Session, err = mgo.Dial("mongodb://localhost:27017/" + database)
	if err != nil {
		fmt.Println(err)
		return
	}
	// Cleanup
	defer checkDB.Session.Close()
	var cAdmins = checkDB.BootstrapAdmins(checkDB.Session)
	var cPeople = checkDB.BootstrapPeople(checkDB.Session)
	var cPizza = checkDB.BootstrapPizza(checkDB.Session)
	var cOrder = checkDB.BootstrapOrder(checkDB.Session)
	admins := &Collection{C: cAdmins}
	people := &Collection{C: cPeople}
	orders := &Collection{C: cOrder}
	pizza := &Collection{C: cPizza}
	readPeople(cPeople)
	readAdmins(cAdmins)
	checkDB.ReadOrder(cOrder)
	fmt.Println("main() -> pizza ->", pizza)
	r := gin.Default()
	r.LoadHTMLGlob("templates/*.html")
	////////////////////////////////////////////////
	r.Static("./admin/png", "./templates")
	r.Static("/user/css", "./templates")
	r.Static("/admin/css", "./templates")
	////////////////////////////////////////////////
	r.GET("/page", func(c *gin.Context) {
		c.HTML(http.StatusOK, "page.html", gin.H{
			"title": "test",
		})
	})
	/////////////////////////////////////// ROUTE ADMIN/////////////////////////////////////////////////
	routeAdmins := r.Group("/admin")
	{
		routeAdmins.GET("/", func(c *gin.Context) {
			pin := "3"
			if checkDB.RequestPin.PinAdm != pin {
				c.HTML(http.StatusForbidden, "page.html", gin.H{
					"pin": "Пароль неверный",
				})
				return
			} else {
				c.HTML(http.StatusOK, "Admin.html", gin.H{
					"pin": "Пароль верный",
				})
			}

		})
		routeAdmins.POST("/checkPinAdm", checkDB.CheckPinAdm)
		routeAdmins.POST("/login", loginAdmin)
		routeAdmins.POST("/signUp", admins.signUpAdmins)
		routeAdmins.GET("/userList", func(c *gin.Context) {
			var elems []string
			for k, v := range cacheUser.Items {
				fmt.Println(k, v)
				elems = append(elems, k)
				fmt.Println(elems)
			}
			fmt.Println(elems)
			c.JSON(200, elems)
		})
		routeAdmins.Use(token.CheckTokenValidationAdmins)
		routeAdmins.POST("/sendPizza", savePizzaAdmin)
		routeAdmins.GET("/logOut", logoutAdmin)
		routeAdmins.DELETE("/banUser", people.banUser)
	}
	/////////////////////////////////////// ROUTE USER/////////////////////////////////////////////////
	routeUser := r.Group("/user")
	{
		routeUser.GET("/", func(c *gin.Context) {
			cookieStatus, _ := c.Cookie("status")
			if cookieStatus == "admin" {
				c.String(http.StatusForbidden, "Error", cookieStatus)
				return
			}
			_, err := c.Cookie("token")
			cookieEMAIL, _ := c.Cookie("email")
			if err != nil {
				c.HTML(http.StatusOK, "User.html", nil)
			} else {
				c.HTML(200, "accountUser.html", gin.H{
					"email": cookieEMAIL,
				})
			}
		})
		routeUser.POST("/signUp", people.signUpUsers)
		routeUser.POST("/login", orders.loginUser)
		/////////////////////////////////////////////
		routeUser.Use(token.CheckTokenValidationUsers)
		routeUser.GET("/logOut", logoutUser)
		routeUser.GET("/pizza", func(c *gin.Context) {

			c.HTML(http.StatusOK, "pizza.html", nil)
		})
		routeUser.GET("/pay", func(c *gin.Context) {
			for k := range paymentArray {
				c.HTML(http.StatusOK, "pay.html", gin.H{
					"orderName":   paymentArray[k].Email,
					"orderStatus": "Не оплачен",
					"orderPizza":  paymentArray[k].OrderedPizza,
					"orderData":   paymentArray[k].DataUser,
					"orderSum":    sum,
				})
			}
		})

		routeUser.GET("/getPizza", func(c *gin.Context) {
			orderPizzas := checkDB.Order.Pizzas
			c.JSON(200, orderPizzas)
		})
		routeUser.GET("/choosePizzas", func(c *gin.Context) {
			c.JSON(200, resultsPizzaAdm)
		})
		routeUser.DELETE("/pizzaDelete", orders.deletePizzaFromTrash)
		routeUser.DELETE("/unCheckPizza", unCheckOrderedPizza)
		routeUser.POST("/orderPizza", orders.pizzaOrder)
		routeUser.POST("/checkPizza", checkOrderedPizza)
		routeUser.POST("/pay", paymentPizza)
		routeUser.POST("/payPayed", payedOrder)
	}
	/////////////////////////////////////////////////////////////////////////////////////////////////////
	err1 := r.Run()
	if err1 != nil {
		panic(err1)
	}
}
