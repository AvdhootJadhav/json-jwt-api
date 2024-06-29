package main

import (
	"log"
)

func main() {
	store, err := NewPostgresStore()
	if err != nil {
		log.Fatalln(err)
	}

	if err := store.Init(); err != nil {
		log.Fatalln(err)
	}

	server := NewAPIServer(":3000", store)
	server.Run()

}
