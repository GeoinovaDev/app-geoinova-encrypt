package encrypt

var current Encrypt

func SetEncrypt(crypto Encrypt) {
	current = crypto
}

func EncodeString(str string) string {
	return current.Encode(str)
}

func DecodeString(str string) string {
	return current.Decode(str)
}
