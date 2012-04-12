package radius
import (
	"errors"
)
func Authenticate(user, pass string) error {
	if user == "bob" && pass=="hello" {
		return nil
	}
	return errors.New("bad username or password")
}
