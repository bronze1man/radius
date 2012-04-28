package main

import (
	"log"
	"github.com/jessta/radius"
)

func main(){
	s := radius.NewServer(":1812","sEcReT")
	s.RegisterService("127.0.0.1" , &radius.PasswordService{})
	log.Println("waiting for packets...")
	err := s.ListenAndServe()
	if err != nil{
		log.Fatalln(err)
	}
}
