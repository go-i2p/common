package exportable

import common "github.com/go-i2p/common/certificate"

func Fuzz(data []byte) int {
	cert, _, _ := common.ReadCertificate(data)
	cert.Data()
	cert.Length()
	cert.Type()
	return 0
}
