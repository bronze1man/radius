package radius

import (
	"reflect"
	"testing"
)

func TestClientList(t *testing.T) {
	herd := []Client{
		NewClient("1.1.1.1", "secret1"),
		NewClient("2.2.2.2", "secret2"),
	}
	cls := NewClientList(herd)

	ok(reflect.DeepEqual(cls.GetHerd(), herd))

	newClient := NewClient("3.3.3.3", "secret3")
	cls.AddOrUpdate(newClient)
	ok(reflect.DeepEqual(cls.Get("3.3.3.3"), newClient))
	ok(len(cls.GetHerd()) == 3)

	updateClient := NewClient("1.1.1.1", "updatesecret")
	cls.AddOrUpdate(updateClient)
	ok(reflect.DeepEqual(cls.Get("1.1.1.1"), updateClient))
	ok(len(cls.GetHerd()) == 3)

	cls.Remove("3.3.3.3")
	println(cls.Get("3.3.3.3"))
	ok(cls.Get("3.3.3.3") == nil)
	ok(len(cls.GetHerd()) == 2)
}
