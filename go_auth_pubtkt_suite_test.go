package pubtkt_test

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"testing"
)

func TestGoAuthPubtkt(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "GoAuthPubtkt Suite")
}
