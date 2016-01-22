package main

import (
	"encoding/hex"
	"fmt"

        "github.com/coreos/go-tspi/tspi"
	"github.com/coreos/go-tspi/tspiconst"
)

func main() {
	context, _ := tspi.NewContext()
	context.Connect()
	
        pcrs, _ := context.CreatePCRs(tspiconst.TSS_PCRS_STRUCT_INFO)

	pcrs.SetPCRs([]int{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15})
	
}
