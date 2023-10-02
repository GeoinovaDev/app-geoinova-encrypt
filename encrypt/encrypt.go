package encrypt

type Encrypt struct {
	key string
}

func NewEncrypt(key string) Encrypt {
	return Encrypt{key}
}

func (c Encrypt) Encode(str string) string {
	_str, _ := encode(c.key, str)
	return _str
}

func (c Encrypt) Decode(str string) string {
	_str, _ := decode(c.key, str)
	return _str
}
