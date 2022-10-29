package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
)

func readJsonConfig() map[string]interface{} {
	content, err := os.ReadFile("./config.json")

	if err != nil {
		panic(err)
	}

	// Now let's unmarshall the data into `payload`
	var payload map[string]interface{}
	err = json.Unmarshal(content, &payload)

	if err != nil {
		panic(err)
	}

	return payload
}

func main() {
	cipherKey := []byte(fmt.Sprintf("%s", readJsonConfig()["aeskey"])) //24 bit key for AES-192

	reader := bufio.NewReader(os.Stdin)
	message := "test"
	//IF no command line argument is given:
	if len(os.Args) != 2 {
		//Get user input
		fmt.Printf("\n\tNo command line argument found, getting user input\n")
		fmt.Printf("\tEnter a string to test: ")
		message, _ = reader.ReadString('\n')
	} else { //Make the message equal to the command line argument
		message = os.Args[1]
	}

	//Encrypt the text:
	encrypted, err := encrypt(cipherKey, message)

	//IF the encryption failed:
	if err != nil {
		//Print error message:
		log.Println(err)
		os.Exit(-2)
	}

	//Print the key and cipher text:
	//fmt.Printf("\n\tCIPHER KEY: %s\n", string(cipherKey))
	fmt.Printf("\tENCRYPTED: %s\n", encrypted)

	//Decrypt the text:
	decrypted, err := decrypt(cipherKey, encrypted)

	//IF the decryption failed:
	if err != nil {
		log.Println(err)
		os.Exit(-3)
	}

	//Print re-decrypted text:
	fmt.Printf("\tDECRYPTED: %s\n\n", decrypted)
}

func encrypt(key []byte, message string) (encoded string, err error) {
	//Create byte array from the input string
	plainText := []byte(message)

	//Create a new AES cipher using the key
	block, err := aes.NewCipher(key)

	//IF NewCipher failed, exit:
	if err != nil {
		return
	}

	//Make the cipher text a byte array of size BlockSize + the length of the message
	cipherText := make([]byte, aes.BlockSize+len(plainText))

	//iv is the ciphertext up to the blocksize (16)
	iv := cipherText[:aes.BlockSize]
	if _, err = io.ReadFull(rand.Reader, iv); err != nil {
		return
	}

	//Encrypt the data:
	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(cipherText[aes.BlockSize:], plainText)

	//Return string encoded in base64
	return base64.RawStdEncoding.EncodeToString(cipherText), err
}

func decrypt(key []byte, secure string) (decoded string, err error) {
	//Remove base64 encoding:
	cipherText, err := base64.RawStdEncoding.DecodeString(secure)

	//IF DecodeString failed, exit:
	if err != nil {
		return
	}

	//Create a new AES cipher with the key and encrypted message
	block, err := aes.NewCipher(key)

	//IF NewCipher failed, exit:
	if err != nil {
		return
	}

	//IF the length of the cipherText is less than 16 Bytes:
	if len(cipherText) < aes.BlockSize {
		err = errors.New("ciphertext block size is too short")
		return
	}

	iv := cipherText[:aes.BlockSize]
	cipherText = cipherText[aes.BlockSize:]

	//Decrypt the message
	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(cipherText, cipherText)

	return string(cipherText), err
}
