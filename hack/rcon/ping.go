package main

import (
	"fmt"
	"os"

	"github.com/glorfischi/factoriod/pkg/rcon"
)

func main() {
	c, err := rcon.Dial("localhost:7000", rcon.WithPassword("test123456"))
	if err != nil {
		panic(err)
	}

	resp, err := c.Command(os.Args[1])
	if err != nil {
		panic(err)
	}
	fmt.Println(resp)
}
