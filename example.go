package main

import (
	"fmt"
	"go/gggpay"
)

// Here is an example of a gggpay sdk
func main() {

	// docs : https://doc.gggpay.org/docs/quickstart/setup
	// payment-method: https://doc.gggpay.org/docs/appendix/payment-method
	// dictionary : https://doc.gggpay.org/docs/appendix/dictionary

	// initialize this configuration
	// verNo GGGPay Api Version Number, default: v1
	// apiUrl GGGPay Api Url
	// appId in developer settings : App Id
	// key in developer settings : Key
	// secret in developer settings : secret
	// serverPubKey in developer settings : Server Public Key
	// privateKey in developer settings : Private Key
	// gggpay.Init(verNo, apiUrl, appId, key, secret, serverPubKey, privateKey)

	// Here is an example of a deposit
	depositResult := gggpay.Deposit("10001", 1.06, "MYR", "TNG_MY", "GGGPay Test", "gggpay@hotmail.com", "0123456789")
	fmt.Println(depositResult)

	// Here is an example of a withdraw
	withdrawResult := gggpay.Withdraw("10012", 1.06, "MYR", "CIMB", "GGGPay Test", "234719327401231", "", "gggpay@hotmail.com", "0123456789")
	fmt.Println(withdrawResult)

	// Here is an example of a detail
	detailResult := gggpay.Detail("10854", 1)
	fmt.Println(detailResult)

	// Decrypt the encrypted information in the callback
	jsonsStr := gggpay.SymDecrypt("encryptedData .........")
	fmt.Println(jsonsStr)
}
